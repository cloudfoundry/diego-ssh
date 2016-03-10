package main

import (
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/cloudfoundry-incubator/cf-debug-server"
	"github.com/cloudfoundry-incubator/cf-lager"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/keys"
	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
	"golang.org/x/crypto/ssh"
)

var address = flag.String(
	"address",
	"127.0.0.1:2222",
	"listen address for ssh daemon",
)

var hostKey = flag.String(
	"hostKey",
	"",
	"PEM encoded RSA host key",
)

var authorizedKey = flag.String(
	"authorizedKey",
	"",
	"Public key in the OpenSSH authorized_keys format",
)

var allowUnauthenticatedClients = flag.Bool(
	"allowUnauthenticatedClients",
	false,
	"Allow access to unauthenticated clients",
)

var inheritDaemonEnv = flag.Bool(
	"inheritDaemonEnv",
	false,
	"Inherit daemon's environment",
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

func main() {
	cf_debug_server.AddFlags(flag.CommandLine)
	cf_lager.AddFlags(flag.CommandLine)
	flag.Parse()

	logger, reconfigurableSink := cf_lager.New("sshd")

	serverConfig, err := configure(logger)
	if err != nil {
		logger.Error("configure-failed", err)
		os.Exit(1)
	}

	sshDaemon := daemon.New(logger, serverConfig, nil, newChannelHandlers())
	server, err := createServer(logger, *address, sshDaemon)

	members := grouper.Members{
		{"sshd", server},
	}

	if dbgAddr := cf_debug_server.DebugAddress(flag.CommandLine); dbgAddr != "" {
		members = append(grouper.Members{
			{"debug-server", cf_debug_server.Runner(dbgAddr, reconfigurableSink)},
		}, members...)
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

func getDaemonEnvironment() map[string]string {
	daemonEnv := map[string]string{}

	if *inheritDaemonEnv {
		envs := os.Environ()
		for _, env := range envs {
			nvp := strings.SplitN(env, "=", 2)
			if len(nvp) == 2 && nvp[0] != "PATH" {
				daemonEnv[nvp[0]] = nvp[1]
			}
		}
	}
	return daemonEnv
}

func configure(logger lager.Logger) (*ssh.ServerConfig, error) {
	errorStrings := []string{}
	sshConfig := &ssh.ServerConfig{}

	key, err := acquireHostKey(logger)
	if err != nil {
		logger.Error("failed-to-acquire-host-key", err)
		errorStrings = append(errorStrings, err.Error())
	}

	sshConfig.AddHostKey(key)
	sshConfig.NoClientAuth = *allowUnauthenticatedClients

	if *authorizedKey == "" && !*allowUnauthenticatedClients {
		logger.Error("authorized-key-required", nil)
		errorStrings = append(errorStrings, "Public user key is required")
	}

	if *authorizedKey != "" {
		decodedPublicKey, err := decodeAuthorizedKey(logger)
		if err == nil {
			authenticator := authenticators.NewPublicKeyAuthenticator(decodedPublicKey)
			sshConfig.PublicKeyCallback = authenticator.Authenticate
		} else {
			errorStrings = append(errorStrings, err.Error())
		}
	}

	if *allowedCiphers != "" {
		sshConfig.Config.Ciphers = strings.Split(*allowedCiphers, ",")
	}
	if *allowedMACs != "" {
		sshConfig.Config.MACs = strings.Split(*allowedMACs, ",")
	}
	if *allowedKeyExchanges != "" {
		sshConfig.Config.KeyExchanges = strings.Split(*allowedKeyExchanges, ",")
	}

	err = nil
	if len(errorStrings) > 0 {
		err = errors.New(strings.Join(errorStrings, ", "))
	}

	return sshConfig, err
}

func decodeAuthorizedKey(logger lager.Logger) (ssh.PublicKey, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*authorizedKey))
	return publicKey, err
}

func acquireHostKey(logger lager.Logger) (ssh.Signer, error) {
	var encoded []byte
	if *hostKey == "" {
		hostKeyPair, err := keys.RSAKeyPairFactory.NewKeyPair(1024)

		if err != nil {
			logger.Error("failed-to-generate-host-key", err)
			return nil, err
		}
		encoded = []byte(hostKeyPair.PEMEncodedPrivateKey())
	} else {
		encoded = []byte(*hostKey)
	}

	key, err := ssh.ParsePrivateKey(encoded)
	if err != nil {
		logger.Error("failed-to-parse-host-key", err)
		return nil, err
	}
	return key, nil
}
