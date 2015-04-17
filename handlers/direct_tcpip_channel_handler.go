package handlers

import (
	"fmt"
	"net"
	"sync"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter -o fakes/fake_dialer.go . Dialer
type Dialer interface {
	Dial(net, addr string) (net.Conn, error)
}

type DirectTcpipChannelHandler struct {
	dialer Dialer
}

func NewDirectTcpipChannelHandler(dialer Dialer) *DirectTcpipChannelHandler {
	return &DirectTcpipChannelHandler{
		dialer: dialer,
	}
}

func (handler *DirectTcpipChannelHandler) HandleNewChannel(logger lager.Logger, newChannel ssh.NewChannel) {
	type channelOpenDirectTcpipMsg struct {
		TargetAddr string
		TargetPort uint32
		OriginAddr string
		OriginPort uint32
	}
	var directTcpipMessage channelOpenDirectTcpipMsg

	err := ssh.Unmarshal(newChannel.ExtraData(), &directTcpipMessage)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "Failed to parse open channel message")
		return
	}

	destination := fmt.Sprintf("%s:%d", directTcpipMessage.TargetAddr, directTcpipMessage.TargetPort)
	conn, err := handler.dialer.Dial("tcp", destination)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, requests, err := newChannel.Accept()
	go ssh.DiscardRequests(requests)

	wg := &sync.WaitGroup{}

	wg.Add(2)
	go helpers.CopyAndClose(logger.Session("to-target"), wg, conn, channel)
	go helpers.CopyAndClose(logger.Session("to-channel"), wg, channel, conn)

	wg.Wait()
}
