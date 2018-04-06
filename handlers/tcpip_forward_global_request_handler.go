package handlers

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"code.cloudfoundry.org/diego-ssh/helpers"
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

func (h *TcpipForwardGlobalRequestHandler) HandleRequest(logger lager.Logger, request *ssh.Request, conn ssh.Conn) {
	logger = logger.Session("tcpip-forward", lager.Data{
		"type":       request.Type,
		"want-reply": request.WantReply,
	})
	logger.Info("start")
	defer logger.Info("done")

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

	address := net.JoinHostPort(tcpipForwardMessage.Address, strconv.FormatUint(uint64(tcpipForwardMessage.Port), 10))

	logger.Info("new-tcpip-forward", lager.Data{
		"message-address": tcpipForwardMessage.Address,
		"message-port":    tcpipForwardMessage.Port,
		"listen-address":  address,
	})

	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Error("failed-to-listen", err)
		_ = request.Reply(false, nil)
		return // CEV: This was missing and causing forwardAcceptLoop to panic
	}

	h.listeners[address] = listener

	go h.forwardAcceptLoop(listener, logger, conn)

	var tcpipForwardResponse struct {
		Port uint32
	}
	if lnAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		tcpipForwardResponse.Port = uint32(lnAddr.Port)
	}

	var replyPayload []byte

	if tcpipForwardMessage.Port == 0 {
		replyPayload = ssh.Marshal(tcpipForwardResponse)
	}

	// Reply() will only send something when WantReply is true
	_ = request.Reply(true, replyPayload)
}

// See RFC 4254, section 7.2
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// CEV: here we need to figure out what to do with the listener...
// EX: We need to start a new channel for each accepted connection, so we need to do this with the SSH Conn
func (h *TcpipForwardGlobalRequestHandler) forwardAcceptLoop(listener net.Listener, logger lager.Logger, sshConn ssh.Conn) {
	logger = logger.Session("forwardAcceptLoop")
	logger.Info("start")
	defer logger.Info("done")

	defer func() {
		if e := recover(); e != nil {
			logger.Error("PANIC", fmt.Errorf("%#v  --  %s", e, e), lager.Data{"panic": e})
		} else {
			logger.Info("clean-exit")
		}
	}()

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("failed-to-accept", err)
			return
		}

		channel, requests, err := sshConn.OpenChannel("some-forwarded-tcpip-ch-name", nil)
		if err != nil {
			logger.Error("failed-to-open channel", err)
			continue
		}
		go ssh.DiscardRequests(requests)
		go func() {
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
		}()

		logger.Info("accepted-connection", lager.Data{"Address": listener.Addr().String()})
	}
}
