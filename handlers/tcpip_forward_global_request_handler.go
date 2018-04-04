package handlers

import (
	"net"
	"strconv"

	"code.cloudfoundry.org/lager"
	"golang.org/x/crypto/ssh"
)

const TCP_IP_FORWARD = "tcpip-forward"

type TcpipForwardGlobalRequestHandler struct {
	listeners map[string]net.Listener
}

func NewTcpipForwardGlobalRequestHandler() *TcpipForwardGlobalRequestHandler {
	return &TcpipForwardGlobalRequestHandler{
		listeners: make(map[string]net.Listener),
	}
}

func (h *TcpipForwardGlobalRequestHandler) HandleRequest(logger lager.Logger, request *ssh.Request) {
	logger = logger.Session("tcpip-forward")

	type tcpipForwardMsg struct {
		Address string
		Port    uint32
	}
	var tcpipForwardMessage tcpipForwardMsg

	err := ssh.Unmarshal(request.Payload, &tcpipForwardMessage)
	if err != nil {
		logger.Error("unmarshal-failed", err)
		request.Reply(false, nil)
	}

	logger.Info("new-tcpip-forward", lager.Data{
		"Address": tcpipForwardMessage.Address,
		"Port":    tcpipForwardMessage.Port,
	})

	address := net.JoinHostPort(tcpipForwardMessage.Address, strconv.FormatUint(uint64(tcpipForwardMessage.Port), 10))

	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Error("failed-to-listen", err)
		request.Reply(false, nil)
	}

	h.listeners[address] = listener

	go h.forwardAcceptLoop(listener, logger)

	// if request.WantReply {
	// 	//TODO do stuff
	// }
}

func (h *TcpipForwardGlobalRequestHandler) forwardAcceptLoop(listener net.Listener, logger lager.Logger) {
	defer listener.Close()

	_, err := listener.Accept()
	if err != nil {
		logger.Error("failed-to-accept", err)
		return
	}

	logger.Info("accepted-connection", lager.Data{"Address": listener.Addr().String()})
}
