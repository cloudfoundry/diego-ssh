// +build windows

package handlers

import (
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type SessionChannelHandler struct {
}

func NewSessionChannelHandler() *SessionChannelHandler {
	return &SessionChannelHandler{}
}

func (handler *SessionChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	err := newChannel.Reject(ssh.Prohibited, "SSH is not supported on windows cells")
	if err != nil {
		logger.Error("handle-new-session-channel-failed", err)
	}

	return
}
