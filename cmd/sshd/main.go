package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/cloudfoundry-incubator/cf-debug-server"
	"github.com/cloudfoundry-incubator/cf-lager"
	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
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

var publicUserKey = flag.String(
	"publicUserKey",
	"",
	"PEM encoded RSA public key to use for user authentication",
)

var allowUnauthenticatedClients = flag.Bool(
	"allowUnauthenticatedClients",
	false,
	"Allow access to unauthenticated clients",
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

	sshDaemon := daemon.New(
		logger,
		serverConfig,
		nil,
		map[string]handlers.NewChannelHandler{
			"session": &handlers.SessionChannelHandler{},
		},
	)
	server := server.NewServer(logger, *address, sshDaemon)

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

func configure(logger lager.Logger) (*ssh.ServerConfig, error) {
	errorStrings := []string{}
	sshConfig := &ssh.ServerConfig{}

	if *hostKey == "" {
		logger.Error("host-key-required", nil)
		errorStrings = append(errorStrings, "Host key is required")
	}

	key, err := ssh.ParsePrivateKey([]byte(*hostKey))
	if err != nil {
		logger.Error("failed-to-parse-host-key", err)
		errorStrings = append(errorStrings, "Failed to parse host key")
	}
	sshConfig.AddHostKey(key)
	sshConfig.NoClientAuth = *allowUnauthenticatedClients

	if *publicUserKey == "" && !*allowUnauthenticatedClients {
		logger.Error("public-user-key-required", nil)
		errorStrings = append(errorStrings, "Public user key is required")
	}

	if *publicUserKey != "" {
		marshaledUserPublicKey, err := marshalPublicUserKey(logger)
		if err == nil {
			sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(key.Marshal(), marshaledUserPublicKey) {
					return &ssh.Permissions{}, nil
				}

				return nil, errors.New("authentication failed")
			}
		} else {
			errorStrings = append(errorStrings, err.Error())
		}
	}

	err = nil
	if len(errorStrings) > 0 {
		err = errors.New(strings.Join(errorStrings, ", "))
	}

	return sshConfig, err
}

func marshalPublicUserKey(logger lager.Logger) ([]byte, error) {
	block, _ := pem.Decode([]byte(*publicUserKey))
	if block == nil {
		logger.Error("invalid-public-user-key", nil)
		return nil, errors.New("Failed to decode public user key")
	}

	serverPublicKeyRaw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Error("failed-to-parse-public-user-key", err)
		return nil, errors.New("Failed to parse public user key")
	}

	serverPublicKey, err := ssh.NewPublicKey(serverPublicKeyRaw)
	if err != nil {
		logger.Error("failed-to-construct-public-user-key", err)
		return nil, errors.New("Failed to construct public user key")
	}

	return serverPublicKey.Marshal(), nil
}
