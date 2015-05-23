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
	copier, err := scp.New(cmd, channel, channel, channel.Stderr())
	if err != nil {
		return err
	}

	return copier.Copy()
}
