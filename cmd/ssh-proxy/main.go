package main

import (
	"errors"
	"flag"
	"net/url"
	"os"

	"github.com/cloudfoundry-incubator/cf-debug-server"
	"github.com/cloudfoundry-incubator/cf-lager"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/config_factories"
	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	"github.com/cloudfoundry-incubator/receptor"
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

var privateKey = flag.String(
	"privateKey",
	"",
	"PEM encoded RSA private key for authentication",
)

var diegoAPIURL = flag.String(
	"diegoAPIURL",
	"",
	"URL of diego API",
)

func main() {
	cf_debug_server.AddFlags(flag.CommandLine)
	cf_lager.AddFlags(flag.CommandLine)
	flag.Parse()

	logger, reconfigurableSink := cf_lager.New("ssh-proxy")

	proxyConfig, err := configure(logger)
	if err != nil {
		logger.Error("configure-failed", err)
		os.Exit(1)
	}

	key, err := parsePrivateKey(logger, *privateKey)
	if err != nil {
		logger.Fatal("failed-to-parse-private-key", err)
	}

	configFactory := config_factories.NewDiegoConfigFactory(logger, key)
	sshProxy := proxy.New(logger, proxyConfig, configFactory)
	server := server.NewServer(logger, *address, sshProxy)

	members := grouper.Members{
		{"ssh-proxy", server},
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

func configure(logger lager.Logger) (*ssh.ServerConfig, error) {
	if *diegoAPIURL == "" {
		err := errors.New("digoAPIURL is required")
		logger.Fatal("failed-to-acquire-host-key", err)
	}

	url, err := url.Parse(*diegoAPIURL)
	if err != nil {
		logger.Fatal("failed-to-parse-diego-api-url", err)
	}

	var diegoCreds string
	if url.User != nil {
		diegoCreds = url.User.String()
	} else {
		diegoCreds = ":"
	}

	receptorClient := receptor.NewClient(*diegoAPIURL)
	diegoAuthenticator := authenticators.NewDiegoPasswordAuthenticator(logger, receptorClient, []byte(diegoCreds))

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: diegoAuthenticator.Authenticate,
	}

	if *hostKey == "" {
		logger.Fatal("hostKey is required", errors.New("missing hostKey"))
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
