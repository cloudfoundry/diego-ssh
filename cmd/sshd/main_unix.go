// +build !windows

package main

import (
	"code.cloudfoundry.org/diego-ssh/server"
	"github.com/ErikDubbelboer/gspt"
	"github.com/pivotal-golang/lager"
)

func createServer(
	logger lager.Logger,
	address string,
	sshDaemon server.ConnectionHandler,
) (*server.Server, error) {
	gspt.SetProcTitle("diego-sshd process")
	return server.NewServer(logger, address, sshDaemon), nil
}
