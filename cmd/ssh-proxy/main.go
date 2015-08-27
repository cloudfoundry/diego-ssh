package main

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"time"

	"github.com/cloudfoundry-incubator/cf-debug-server"
	"github.com/cloudfoundry-incubator/cf-lager"
	"github.com/cloudfoundry-incubator/cf_http"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry/dropsonde"
	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
	"golang.org/x/crypto/ssh"
)

var address = flag.String(
	"address",
	":2222",
	"listen address for ssh proxy",
)

var hostKey = flag.String(
	"hostKey",
	"",
	"PEM encoded RSA host key",
)

var diegoAPIURL = flag.String(
	"diegoAPIURL",
	"",
	"URL of diego API",
)

var ccAPIURL = flag.String(
	"ccAPIURL",
	"",
	"URL of Cloud Controller API",
)

var communicationTimeout = flag.Duration(
	"communicationTimeout",
	10*time.Second,
	"Timeout applied to all HTTP requests.",
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

const (
	dropsondeDestination = "localhost:3457"
	dropsondeOrigin      = "ssh-proxy"
)

func main() {
	cf_debug_server.AddFlags(flag.CommandLine)
	cf_lager.AddFlags(flag.CommandLine)
	flag.Parse()

	logger, reconfigurableSink := cf_lager.New("ssh-proxy")

	initializeDropsonde(logger)

	proxyConfig, err := configure(logger)
	if err != nil {
		logger.Error("configure-failed", err)
		os.Exit(1)
	}

	sshProxy := proxy.New(logger, proxyConfig)
	server := server.NewServer(logger, *address, sshProxy)

	members := grouper.Members{
		{"ssh-proxy", server},
	}

	if dbgAddr := cf_debug_server.DebugAddress(flag.CommandLine); dbgAddr != "" {
		members = append(grouper.Members{{
			"debug-server", cf_debug_server.Runner(dbgAddr, reconfigurableSink),
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

func initializeDropsonde(logger lager.Logger) {
	err := dropsonde.Initialize(dropsondeDestination, dropsondeOrigin)
	if err != nil {
		logger.Error("failed-to-initialize-dropsonde", err)
	}
}

func configure(logger lager.Logger) (*ssh.ServerConfig, error) {
	cf_http.Initialize(*communicationTimeout)

	if *diegoAPIURL == "" {
		err := errors.New("diegoAPIURL is required")
		logger.Fatal("diego-api-url-required", err)
	}

	url, err := url.Parse(*diegoAPIURL)
	if err != nil {
		logger.Fatal("failed-to-parse-diego-api-url", err)
	}

	_, err = url.Parse(*ccAPIURL)
	if *ccAPIURL != "" && err != nil {
		logger.Fatal("failed-to-parse-cc-api-url", err)
	}

	var diegoCreds string
	if url.User != nil {
		diegoCreds = url.User.String()
	}

	receptorClient := receptor.NewClient(*diegoAPIURL)

	authenticatorMap := map[string]authenticators.PasswordAuthenticator{}

	if *enableDiegoAuth {
		diegoAuthenticator := authenticators.NewDiegoProxyAuthenticator(logger, receptorClient, []byte(diegoCreds))
		authenticatorMap[diegoAuthenticator.Realm()] = diegoAuthenticator
	}

	if *ccAPIURL != "" && *enableCFAuth {
		ccClient := cf_http.NewClient()
		cfAuthenticator := authenticators.NewCFAuthenticator(logger, ccClient, *ccAPIURL, receptorClient)
		authenticatorMap[cfAuthenticator.Realm()] = cfAuthenticator
	}

	authenticator := authenticators.NewCompositeAuthenticator(authenticatorMap)

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: authenticator.Authenticate,
		AuthLogCallback: func(cmd ssh.ConnMetadata, method string, err error) {
			logger.Error("authentication-failed", err, lager.Data{"user": cmd.User()})
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

	return sshConfig, err
}

func parsePrivateKey(logger lager.Logger, encodedKey string) (ssh.Signer, error) {
	key, err := ssh.ParsePrivateKey([]byte(encodedKey))
	if err != nil {
		logger.Error("failed-to-parse-private-key", err)
		return nil, err
	}
	return key, nil
}
