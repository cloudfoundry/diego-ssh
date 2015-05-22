package handlers

import (
	"github.com/cloudfoundry-incubator/diego-ssh/scp"
	"golang.org/x/crypto/ssh"
)

type scpHandler struct {
}

func NewSCPHandler() SCPHandler {
	return &scpHandler{}
}

func (handler *scpHandler) HandleSCPRequest(channel ssh.Channel, request *ssh.Request, cmd string) error {
	scp.New(cmd, channel, channel, channel.Stderr())
	return nil
}
