package handlers

import (
	"fmt"
	"net"
	"os"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
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

	members := grouper.Members{
		{"to-target", helpers.NewCopyRunner(logger.Session("to-target"), conn, channel)},
		{"to-channel", helpers.NewCopyRunner(logger.Session("to-channel"), channel, conn)},
	}

	defer func() {
		conn.Close()
		channel.Close()
	}()

	group := grouper.NewOrdered(os.Interrupt, members)
	monitor := ifrit.Invoke(sigmon.New(group))

	logger.Info("started")

	err = <-monitor.Wait()
	if err != nil {
		logger.Error("exited-with-failure", err)
	}
}
