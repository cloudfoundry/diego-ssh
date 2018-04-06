package handlers

import (
	"fmt"
	"net"
	"sync"

	"code.cloudfoundry.org/diego-ssh/helpers"
	"code.cloudfoundry.org/lager"
	"golang.org/x/crypto/ssh"
)

type DirectTcpipChannelHandler struct {
	dialer Dialer
}

func NewDirectTcpipChannelHandler(dialer Dialer) *DirectTcpipChannelHandler {
	return &DirectTcpipChannelHandler{
		dialer: dialer,
	}
}

func (handler *DirectTcpipChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	logger = logger.Session("direct-tcp-ip-handle-new-channel")
	logger.Info("start")
	defer logger.Info("done")
	defer handlePanic(logger)

	// RFC 4254 Section 7.1
	type channelOpenDirectTcpipMsg struct {
		TargetAddr string
		TargetPort uint32
		OriginAddr string
		OriginPort uint32
	}
	var directTcpipMessage channelOpenDirectTcpipMsg

	err := ssh.Unmarshal(newChannel.ExtraData(), &directTcpipMessage)
	if err != nil {
		logger.Error("failed-unmarshalling-ssh-message", err)
		newChannel.Reject(ssh.ConnectionFailed, "Failed to parse open channel message")
		return
	}
	logger.Info("channel-open-direct-tcp-ip-msg", lager.Data{
		"message": directTcpipMessage,
	})

	destination := fmt.Sprintf("%s:%d", directTcpipMessage.TargetAddr, directTcpipMessage.TargetPort)
	logger.Info("dialing-connection", lager.Data{"destination": destination})
	conn, err := handler.dialer.Dial("tcp", destination)
	if err != nil {
		logger.Error("failed-connecting-to-target", err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	logger.Info("dialed-connection", lager.Data{"destintation": destination})

	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Error("failed-to-accept-channel", err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	go func(logger lager.Logger) {
		logger.Info("start")
		defer logger.Info("done")
		defer handlePanic(logger)
		ssh.DiscardRequests(requests)
	}(logger.Session("discard-requests"))

	wg := &sync.WaitGroup{}

	wg.Add(2)

	defer func() {
		conn.Close()
		channel.Close()
	}()

	logger.Info("copying-channel-data")
	go func(logger lager.Logger) {
		logger.Info("start")
		defer logger.Info("done")
		defer handlePanic(logger)
		helpers.CopyAndClose(logger, wg, conn, channel, func() {
			conn.(*net.TCPConn).CloseWrite()
		})
	}(logger.Session("to-target"))

	go func(logger lager.Logger) {
		logger.Info("start")
		defer logger.Info("done")
		defer handlePanic(logger)
		helpers.CopyAndClose(logger, wg, channel, conn, func() {
			channel.CloseWrite()
		})
	}(logger.Session("to-channel"))

	wg.Wait()
}
