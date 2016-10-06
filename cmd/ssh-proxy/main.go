package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/cfhttp"
	"code.cloudfoundry.org/cflager"
	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/consuladapter"
	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/diego-ssh/authenticators"
	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/diego-ssh/proxy"
	"code.cloudfoundry.org/diego-ssh/server"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/locket"
	"github.com/cloudfoundry/dropsonde"
	"github.com/hashicorp/consul/api"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
	"golang.org/x/crypto/ssh"
)

var address = flag.String(
	"address",
	":2222",
	"listen address for ssh proxy",
)

var healthCheckAddress = flag.String(
	"healthCheckAddress",
	":2223",
	"listen address for ssh proxy health check server",
)

var hostKey = flag.String(
	"hostKey",
	"",
	"PEM encoded RSA host key",
)

var bbsAddress = flag.String(
	"bbsAddress",
	"",
	"Address of the BBS API Server",
)

var ccAPIURL = flag.String(
	"ccAPIURL",
	"",
	"URL of Cloud Controller API",
)

var uaaTokenURL = flag.String(
	"uaaTokenURL",
	"",
	"URL of the UAA OAuth2 token endpoint that includes the oauth client ID and password",
)

var uaaPassword = flag.String(
	"uaaPassword",
	"",
	"Basic auth password for UAA.",
)

var uaaUsername = flag.String(
	"uaaUsername",
	"",
	"Username for UAA",
)

var skipCertVerify = flag.Bool(
	"skipCertVerify",
	false,
	"skip SSL certificate verification",
)

var communicationTimeout = flag.Duration(
	"communicationTimeout",
	10*time.Second,
	"Timeout applied to all HTTP requests.",
)

var dropsondePort = flag.Int(
	"dropsondePort",
	3457,
	"port the local metron agent is listening on",
)

var enableCFAuth = flag.Bool(
	"enableCFAuth",
	false,
	"Allow authentication with cf",
)

var enableDiegoAuth = flag.Bool(
	"enableDiegoAuth",
	false,
	"Allow authentication with diego",
)

var diegoCredentials = flag.String(
	"diegoCredentials",
	"",
	"Diego Credentials to be used with the Diego authentication method",
)

var bbsCACert = flag.String(
	"bbsCACert",
	"",
	"path to certificate authority cert used for mutually authenticated TLS BBS communication",
)

var bbsClientCert = flag.String(
	"bbsClientCert",
	"",
	"path to client cert used for mutually authenticated TLS BBS communication",
)

var bbsClientKey = flag.String(
	"bbsClientKey",
	"",
	"path to client key used for mutually authenticated TLS BBS communication",
)

var bbsClientSessionCacheSize = flag.Int(
	"bbsClientSessionCacheSize",
	0,
	"Capacity of the ClientSessionCache option on the TLS configuration. If zero, golang's default will be used",
)

var bbsMaxIdleConnsPerHost = flag.Int(
	"bbsMaxIdleConnsPerHost",
	0,
	"Controls the maximum number of idle (keep-alive) connctions per host. If zero, golang's default will be used",
)

var consulCluster = flag.String(
	"consulCluster",
	"",
	"Consul Agent URL",
)

var allowedCiphers = flag.String(
	"allowedCiphers",
	"",
	"Limit cipher algorithms to those provided (comma separated)",
)

var allowedMACs = flag.String(
	"allowedMACs",
	"",
	"Limit MAC algorithms to those provided (comma separated)",
)

var allowedKeyExchanges = flag.String(
	"allowedKeyExchanges",
	"",
	"Limit key exchanges algorithms to those provided (comma separated)",
)

const (
	dropsondeOrigin = "ssh-proxy"
)

func main() {
	debugserver.AddFlags(flag.CommandLine)
	cflager.AddFlags(flag.CommandLine)
	flag.Parse()

	cfhttp.Initialize(*communicationTimeout)

	logger, reconfigurableSink := cflager.New("ssh-proxy")

	initializeDropsonde(logger)

	proxyConfig, err := configureProxy(logger)
	if err != nil {
		logger.Error("configure-failed", err)
		os.Exit(1)
	}

	sshProxy := proxy.New(logger, proxyConfig)
	server := server.NewServer(logger, *address, sshProxy)

	healthCheckHandler := handlers.NewHealthCheckHandler(logger)
	httpServer := http_server.New(*healthCheckAddress, http.DefaultServeMux)
	http.HandleFunc("/", healthCheckHandler.HealthCheck)

	consulClient, err := consuladapter.NewClientFromUrl(*consulCluster)
	if err != nil {
		logger.Fatal("new-client-failed", err)
	}

	registrationRunner := initializeRegistrationRunner(logger, consulClient, *address, clock.NewClock())

	members := grouper.Members{
		{"ssh-proxy", server},
		{"registration-runner", registrationRunner},
		{"healthcheck", httpServer},
	}

	if dbgAddr := debugserver.DebugAddress(flag.CommandLine); dbgAddr != "" {
		members = append(grouper.Members{{
			"debug-server", debugserver.Runner(dbgAddr, reconfigurableSink),
		}}, members...)
	}

	group := grouper.NewOrdered(os.Interrupt, members)
	monitor := ifrit.Invoke(sigmon.New(group))

	logger.Info("started")

	err = <-monitor.Wait()
	if err != nil {
		logger.Error("exited-with-failure", err)
		os.Exit(1)
	}

	logger.Info("exited")
	os.Exit(0)
}

func configureProxy(logger lager.Logger) (*ssh.ServerConfig, error) {
	if *bbsAddress == "" {
		err := errors.New("bbsAddress is required")
		logger.Fatal("bbs-address-required", err)
	}

	url, err := url.Parse(*bbsAddress)
	if err != nil {
		logger.Fatal("failed-to-parse-bbs-address", err)
	}

	bbsClient := initializeBBSClient(logger)
	permissionsBuilder := authenticators.NewPermissionsBuilder(bbsClient)

	authens := []authenticators.PasswordAuthenticator{}

	if *enableDiegoAuth {
		diegoAuthenticator := authenticators.NewDiegoProxyAuthenticator(logger, []byte(*diegoCredentials), permissionsBuilder)
		authens = append(authens, diegoAuthenticator)
	}

	if *enableCFAuth {
		if *ccAPIURL == "" {
			return nil, errors.New("ccAPIURL is required for Cloud Foundry authentication")
		}

		_, err = url.Parse(*ccAPIURL)
		if *ccAPIURL != "" && err != nil {
			return nil, err
		}

		if *uaaPassword == "" {
			return nil, errors.New("UAA password is required for Cloud Foundry authentication")
		}

		if *uaaUsername == "" {
			return nil, errors.New("UAA username is required for Cloud Foundry authentication")
		}

		if *uaaTokenURL == "" {
			return nil, errors.New("uaaTokenURL is required for Cloud Foundry authentication")
		}

		_, err = url.Parse(*uaaTokenURL)
		if *uaaTokenURL != "" && err != nil {
			return nil, err
		}

		client := NewHttpClient()
		cfAuthenticator := authenticators.NewCFAuthenticator(
			logger,
			client,
			*ccAPIURL,
			*uaaTokenURL,
			*uaaUsername,
			*uaaPassword,
			permissionsBuilder,
		)
		authens = append(authens, cfAuthenticator)
	}

	authenticator := authenticators.NewCompositeAuthenticator(authens...)

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: authenticator.Authenticate,
		AuthLogCallback: func(cmd ssh.ConnMetadata, method string, err error) {
			if err != nil {
				logger.Error("authentication-failed", err, lager.Data{"user": cmd.User()})
			} else {
				logger.Info("authentication-attempted", lager.Data{"user": cmd.User()})
			}
		},
	}

	if *hostKey == "" {
		err := errors.New("hostKey is required")
		logger.Fatal("host-key-required", err)
	}

	key, err := parsePrivateKey(logger, *hostKey)
	if err != nil {
		logger.Fatal("failed-to-parse-host-key", err)
	}

	sshConfig.AddHostKey(key)

	if *allowedCiphers != "" {
		sshConfig.Config.Ciphers = strings.Split(*allowedCiphers, ",")
	}
	if *allowedMACs != "" {
		sshConfig.Config.MACs = strings.Split(*allowedMACs, ",")
	}
	if *allowedKeyExchanges != "" {
		sshConfig.Config.KeyExchanges = strings.Split(*allowedKeyExchanges, ",")
	}

	return sshConfig, err
}

func initializeDropsonde(logger lager.Logger) {
	dropsondeDestination := fmt.Sprint("localhost:", *dropsondePort)
	err := dropsonde.Initialize(dropsondeDestination, dropsondeOrigin)
	if err != nil {
		logger.Error("failed to initialize dropsonde: %v", err)
	}
}

func parsePrivateKey(logger lager.Logger, encodedKey string) (ssh.Signer, error) {
	key, err := ssh.ParsePrivateKey([]byte(encodedKey))
	if err != nil {
		logger.Error("failed-to-parse-private-key", err)
		return nil, err
	}
	return key, nil
}

func NewHttpClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tlsConfig := &tls.Config{InsecureSkipVerify: *skipCertVerify}
	return &http.Client{
		Transport: &http.Transport{
			Dial:            dialer.Dial,
			TLSClientConfig: tlsConfig,
		},
		Timeout: *communicationTimeout,
	}
}

func initializeBBSClient(logger lager.Logger) bbs.InternalClient {
	bbsURL, err := url.Parse(*bbsAddress)
	if err != nil {
		logger.Fatal("Invalid BBS URL", err)
	}

	if bbsURL.Scheme != "https" {
		return bbs.NewClient(*bbsAddress)
	}

	bbsClient, err := bbs.NewSecureClient(*bbsAddress, *bbsCACert, *bbsClientCert, *bbsClientKey, *bbsClientSessionCacheSize, *bbsMaxIdleConnsPerHost)
	if err != nil {
		logger.Fatal("Failed to configure secure BBS client", err)
	}
	return bbsClient
}

func initializeRegistrationRunner(logger lager.Logger, consulClient consuladapter.Client, listenAddress string, clock clock.Clock) ifrit.Runner {
	_, portString, err := net.SplitHostPort(listenAddress)
	if err != nil {
		logger.Fatal("failed-invalid-listen-address", err)
	}
	portNum, err := net.LookupPort("tcp", portString)
	if err != nil {
		logger.Fatal("failed-invalid-listen-port", err)
	}

	registration := &api.AgentServiceRegistration{
		Name: "ssh-proxy",
		Port: portNum,
		Check: &api.AgentServiceCheck{
			TTL: "3s",
		},
	}

	return locket.NewRegistrationRunner(logger, registration, consulClient, locket.RetryInterval, clock)
}
