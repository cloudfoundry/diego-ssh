package handlers

import (
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter -o fake_handlers/fake_global_request_handler.go . GlobalRequestHandler
type GlobalRequestHandler interface {
	HandleRequest(logger lager.Logger, request *ssh.Request)
}

//go:generate counterfeiter -o fake_handlers/fake_new_channel_handler.go . NewChannelHandler
type NewChannelHandler interface {
	HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel)
}
