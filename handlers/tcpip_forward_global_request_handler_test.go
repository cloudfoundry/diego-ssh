package handlers_test

import (
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"code.cloudfoundry.org/diego-ssh/daemon"
	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/diego-ssh/server"
	fake_server "code.cloudfoundry.org/diego-ssh/server/fakes"
	"code.cloudfoundry.org/diego-ssh/test_helpers"
	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = FDescribe("TcpipForwardGlobalRequestHandler", func() {
	var (
		handler *handlers.TcpipForwardGlobalRequestHandler

		serverSSHConfig *ssh.ServerConfig
		sshd            *daemon.Daemon
		sshClient       *ssh.Client

		echoHandler *fake_server.FakeConnectionHandler
		echoServer  *server.Server
		echoAddress string

		logger *lagertest.TestLogger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("tcpip-forward-test")

		echoHandler = &fake_server.FakeConnectionHandler{}
		echoHandler.HandleConnectionStub = func(conn net.Conn) {
			io.Copy(conn, conn)
			conn.Close()
		}

		echoListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		echoAddress = echoListener.Addr().String()

		echoServer = server.NewServer(logger.Session("echo"), echoAddress, echoHandler, 5*time.Minute)
		echoServer.SetListener(echoListener)
		go echoServer.Serve()

		serverSSHConfig = &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		handler = handlers.NewTcpipForwardGlobalRequestHandler()

		globalRequestHandlers := map[string]handlers.GlobalRequestHandler{
			"tcpip-forward": handler,
		}

		serverNetConn, clientNetConn := test_helpers.Pipe()
		sshd = daemon.New(logger, serverSSHConfig, globalRequestHandlers, nil)

		go sshd.HandleConnection(serverNetConn)

		sshClient = test_helpers.NewClient(clientNetConn, nil)
	})

	AfterEach(func() {
	})

	Context("when a tcpip-forward message is sent", func() {
		It("listens for connections on the interface/port specified", func() {
			listener, err := sshClient.Listen("tcp", echoAddress)
			Expect(err).NotTo(HaveOccurred())

			defer listener.Close()

			done := make(chan struct{})

			go func() {
				GinkgoRecover()
				localConn, err := listener.Accept()
				Expect(err).NotTo(HaveOccurred())

				msg := make([]byte, 5)
				n, err := localConn.Read(msg)
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(5))

				Expect(msg).To(Equal([]byte("Hello")))

				close(done)
			}()

			remoteConn, err := net.Dial("tcp", echoAddress)
			Expect(err).NotTo(HaveOccurred())

			defer remoteConn.Close()

			msg := []byte("Hello")
			n, err := remoteConn.Write(msg)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(msg)))

			Eventually(done).Should(BeClosed())
		})
	})
})
