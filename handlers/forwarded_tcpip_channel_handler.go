package handlers

import (
	"fmt"
	"net"
	"sync"

	"code.cloudfoundry.org/diego-ssh/helpers"
	"code.cloudfoundry.org/lager"
	"golang.org/x/crypto/ssh"
)

type ForwardedTcpipChannelHandler struct {
	dialer Dialer
}

func NewForwardedTcpipChannelHandler(dialer Dialer) *ForwardedTcpipChannelHandler {
	return &ForwardedTcpipChannelHandler{
		dialer: dialer,
	}
}

func (handler *ForwardedTcpipChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	logger = logger.Session("forwardedtcip-handle-new-channel")
	logger.Debug("starting")
	defer logger.Debug("complete")

	// RFC 4254 Section 7.1
	type channelOpenForwardedTcpipMsg struct {
		ConnectedAddr string
		ConnectedPort uint32
		OriginAddr    string
		OriginPort    uint32
	}
	var forwardedTcpipMessage channelOpenForwardedTcpipMsg

	err := ssh.Unmarshal(newChannel.ExtraData(), &forwardedTcpipMessage)
	if err != nil {
		logger.Error("failed-unmarshalling-ssh-message", err)
		newChannel.Reject(ssh.ConnectionFailed, "Failed to parse open channel message")
		return
	}

	destination := fmt.Sprintf("%s:%d", forwardedTcpipMessage.ConnectedAddr, forwardedTcpipMessage.ConnectedPort)
	logger.Debug("dialing-connection", lager.Data{"destination": destination})
	conn, err := handler.dialer.Dial("tcp", destination)
	if err != nil {
		logger.Error("failed-connecting-to-address", err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	logger.Debug("dialed-connection", lager.Data{"destintation": destination})
	channel, requests, err := newChannel.Accept()
	go ssh.DiscardRequests(requests)

	wg := &sync.WaitGroup{}

	wg.Add(2)

	defer func() {
		conn.Close()
		channel.Close()
	}()

	logger.Debug("copying-channel-data")
	go helpers.CopyAndClose(logger.Session("to-target"), wg, conn, channel,
		func() {
			conn.(*net.TCPConn).CloseWrite()
		},
	)
	go helpers.CopyAndClose(logger.Session("to-channel"), wg, channel, conn,
		func() {
			channel.CloseWrite()
		},
	)

	wg.Wait()
}
