package daemon

import (
	"net"

	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/diego-ssh/helpers"
	"code.cloudfoundry.org/lager"
	"golang.org/x/crypto/ssh"
)

type Daemon struct {
	logger                lager.Logger
	serverConfig          *ssh.ServerConfig
	globalRequestHandlers map[string]handlers.GlobalRequestHandler
	newChannelHandlers    map[string]handlers.NewChannelHandler
}

func New(
	logger lager.Logger,
	serverConfig *ssh.ServerConfig,
	globalRequestHandlers map[string]handlers.GlobalRequestHandler,
	newChannelHandlers map[string]handlers.NewChannelHandler,
) *Daemon {
	return &Daemon{
		logger:                logger,
		serverConfig:          serverConfig,
		globalRequestHandlers: globalRequestHandlers,
		newChannelHandlers:    newChannelHandlers,
	}
}

func (d *Daemon) HandleConnection(netConn net.Conn) {
	logger := d.logger.Session("handle-connection")

	logger.Info("started")
	defer logger.Info("completed")
	defer netConn.Close()

	lnStore := helpers.NewListenerStore()

	serverConn, serverChannels, serverRequests, err := ssh.NewServerConn(netConn, d.serverConfig)
	if err != nil {
		logger.Error("handshake-failed", err)
		return
	}

	go d.handleGlobalRequests(logger, serverRequests, serverConn, lnStore)
	go d.handleNewChannels(logger, serverChannels)

	serverConn.Wait()
	lnStore.RemoveAll()
}

// CEV: This is what handles the requests being passed to TcpipForwardGlobalRequestHandler,
// which means that we aren't getting an ssh.NewChannel with it (I think this is true).
//
// I think the above is may be important because (or at least I wrote it) because having
// the ssh.NewChannel would appear to make forwarding (dark magic) easier.
func (d *Daemon) handleGlobalRequests(logger lager.Logger, requests <-chan *ssh.Request, conn ssh.Conn, lnStore *helpers.ListenerStore) {
	logger = logger.Session("handle-global-requests")
	logger.Info("starting")
	defer logger.Info("finished")

	for req := range requests {
		logger.Debug("request", lager.Data{
			"request-type": req.Type,
			"want-reply":   req.WantReply,
		})

		handler, ok := d.globalRequestHandlers[req.Type]
		if ok {
			handler.HandleRequest(logger, req, conn, lnStore)
			continue
		}

		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func (d *Daemon) handleNewChannels(logger lager.Logger, newChannelRequests <-chan ssh.NewChannel) {
	logger = logger.Session("handle-new-channels")
	logger.Info("starting")
	defer logger.Info("finished")

	for newChannel := range newChannelRequests {
		logger.Info("new-channel", lager.Data{
			"channelType": newChannel.ChannelType(),
			"extraData":   newChannel.ExtraData(),
		})

		if handler, ok := d.newChannelHandlers[newChannel.ChannelType()]; ok {
			go handler.HandleNewChannel(logger, newChannel)
			continue
		}

		logger.Info("rejecting-channel", lager.Data{"reason": "unkonwn-channel-type"})
		newChannel.Reject(ssh.UnknownChannelType, newChannel.ChannelType())
	}
}
