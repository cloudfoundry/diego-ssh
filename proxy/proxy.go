package proxy

import (
	"net"
	"sync"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter -o fakes/fake_config_factory.go . ConfigFactory
type ConfigFactory interface {
	Create(permissions *ssh.Permissions) (config *ssh.ClientConfig, address string, err error)
}

type Waiter interface {
	Wait() error
}

type Proxy struct {
	logger        lager.Logger
	serverConfig  *ssh.ServerConfig
	configFactory ConfigFactory
}

func New(
	logger lager.Logger,
	serverConfig *ssh.ServerConfig,
	configFactory ConfigFactory,
) *Proxy {
	return &Proxy{
		logger:        logger,
		serverConfig:  serverConfig,
		configFactory: configFactory,
	}
}

func (p *Proxy) HandleConnection(netConn net.Conn) {
	logger := p.logger.Session("handle-connection")

	logger.Info("started")
	defer logger.Info("completed")
	defer netConn.Close()

	serverConn, serverChannels, serverRequests, err := ssh.NewServerConn(netConn, p.serverConfig)
	if err != nil {
		logger.Error("handshake-failed", err)
		return
	}
	defer serverConn.Close()

	clientConfig, address, err := p.configFactory.Create(serverConn.Permissions)
	if err != nil || clientConfig == nil || address == "" {
		logger.Error("failed-to-create-client-config", err, lager.Data{
			"address": address,
		})
		return
	}

	clientConn, clientChannels, clientRequests, err := p.newClientConn(logger, address, clientConfig)
	if err != nil {
		return
	}
	defer clientConn.Close()

	go ProxyGlobalRequests(logger, clientConn, serverRequests)
	go ProxyGlobalRequests(logger, serverConn, clientRequests)

	go ProxyChannels(logger, clientConn, serverChannels)
	go ProxyChannels(logger, serverConn, clientChannels)

	Wait(logger, serverConn, clientConn)
}

func ProxyGlobalRequests(logger lager.Logger, conn ssh.Conn, reqs <-chan *ssh.Request) {
	logger = logger.Session("proxy-global-requests")

	logger.Info("started")
	defer logger.Info("completed")

	for req := range reqs {
		logger.Info("request", lager.Data{
			"type":      req.Type,
			"wantReply": req.WantReply,
			"payload":   req.Payload,
		})
		success, reply, err := conn.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger.Error("send-request-failed", err)
			continue
		}

		if req.WantReply {
			req.Reply(success, reply)
		}
	}
}

func ProxyChannels(logger lager.Logger, conn ssh.Conn, channels <-chan ssh.NewChannel) {
	logger = logger.Session("proxy-channels")

	logger.Info("started")
	defer logger.Info("completed")
	defer conn.Close()

	for newChannel := range channels {
		logger.Info("new-channel", lager.Data{
			"channelType": newChannel.ChannelType(),
			"extraData":   newChannel.ExtraData(),
		})

		targetChan, targetReqs, err := conn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err != nil {
			logger.Error("failed-to-open-channel", err)
			if openErr, ok := err.(*ssh.OpenChannelError); ok {
				newChannel.Reject(openErr.Reason, openErr.Message)
			} else {
				newChannel.Reject(ssh.ConnectionFailed, err.Error())
			}
			continue
		}

		sourceChan, sourceReqs, err := newChannel.Accept()
		if err != nil {
			targetChan.Close()
			continue
		}

		go func() {
			helpers.Copy(logger.Session("to-target"), nil, targetChan, sourceChan)
			targetChan.CloseWrite()
		}()
		go func() {
			helpers.Copy(logger.Session("to-source"), nil, sourceChan, targetChan)
			sourceChan.CloseWrite()
		}()

		go ProxyRequests(logger, newChannel.ChannelType(), sourceReqs, targetChan)
		go ProxyRequests(logger, newChannel.ChannelType(), targetReqs, sourceChan)
	}
}

func ProxyRequests(logger lager.Logger, channelType string, reqs <-chan *ssh.Request, channel ssh.Channel) {
	logger = logger.Session("proxy-requests", lager.Data{
		"channel-type": channelType,
	})

	logger.Info("started")
	defer logger.Info("completed")
	defer channel.Close()

	for req := range reqs {
		logger.Info("request", lager.Data{
			"type":      req.Type,
			"wantReply": req.WantReply,
			"payload":   req.Payload,
		})
		success, err := channel.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger.Error("send-request-failed", err)
			continue
		}

		if req.WantReply {
			req.Reply(success, nil)
		}
	}
}

func Wait(logger lager.Logger, waiters ...Waiter) {
	wg := &sync.WaitGroup{}
	for _, waiter := range waiters {
		wg.Add(1)
		go func(waiter Waiter) {
			waiter.Wait()
			wg.Done()
		}(waiter)
	}
	wg.Wait()
}

func (p *Proxy) newClientConn(logger lager.Logger, address string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	logger = logger.Session("new-client-conn", lager.Data{
		"address": address,
	})

	nConn, err := net.Dial("tcp", address)
	if err != nil {
		logger.Error("dial-failed", err)
		return nil, nil, nil, err
	}

	conn, ch, req, err := ssh.NewClientConn(nConn, address, config)
	if err != nil {
		logger.Error("handshake-failed", err)
		return nil, nil, nil, err
	}

	return conn, ch, req, nil
}
