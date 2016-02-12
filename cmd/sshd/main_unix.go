// +build !windows

package main

import (
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	"github.com/pivotal-golang/lager"
)

func createServer(
	logger lager.Logger,
	address string,
	sshDaemon server.ConnectionHandler,
) (*server.Server, error) {
	return server.NewServer(logger, address, sshDaemon), nil
}
