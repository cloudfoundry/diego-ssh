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

type TcpipForwardGlobalRequestHandler struct{}

type tcpipForwardMsg struct {
	Address string
	Port    uint32
}

func (h *TcpipForwardGlobalRequestHandler) HandleRequest(logger lager.Logger, request *ssh.Request, conn ssh.Conn, lnStore *helpers.TCPIPListenerStore) {
	logger = logger.Session("tcpip-forward", lager.Data{
		"type":       request.Type,
		"want-reply": request.WantReply,
	})
	logger.Info("start")
	defer logger.Info("done")

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

	lnStore.AddListener(address, listener)

	var (
		listenerAddr string
		listenerPort uint32
	)
	if addr, ok := listener.Addr().(*net.TCPAddr); ok {
		listenerAddr = addr.IP.String()
		listenerPort = uint32(addr.Port)
	}
	logger.Info("actual-listener-address", lager.Data{
		"addr": listenerAddr,
		"port": listenerPort,
	})

	go h.forwardAcceptLoop(listener, logger, conn, tcpipForwardMessage.Address, listenerPort)

	var tcpipForwardResponse struct {
		Port uint32
	}
	tcpipForwardResponse.Port = listenerPort

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
func (h *TcpipForwardGlobalRequestHandler) forwardAcceptLoop(listener net.Listener, logger lager.Logger, sshConn ssh.Conn, lnAddr string, lnPort uint32) {
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

		go func() {
			var (
				remoteAddr string
				remotePort uint32
			)
			if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				remoteAddr = addr.IP.String()
				remotePort = uint32(addr.Port)
			}
			payload := forwardedTCPPayload{
				Addr:       lnAddr,
				Port:       lnPort,
				OriginAddr: remoteAddr,
				OriginPort: remotePort,
			}
			logger.Info("forwardedTCPPayload", lager.Data{
				"payload": payload,
			})

			channel, requests, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(payload))
			if err != nil {
				logger.Error("failed-to-open channel", err)
				logger.Info("open-channel", lager.Data{
					"channel":  channel,
					"requests": requests,
				})
				return
			}
			logger.Info("opened-channel", lager.Data{"payload": payload})
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
					logger.Info("connection-closewrite")
					conn.(*net.TCPConn).CloseWrite()
				},
			)
			go helpers.CopyAndClose(logger.Session("to-channel"), wg, channel, conn,
				func() {
					logger.Info("channel-closewrite")
					channel.CloseWrite()
				},
			)

			wg.Wait()
		}()

		logger.Info("accepted-connection", lager.Data{"Address": listener.Addr().String()})
	}
}
