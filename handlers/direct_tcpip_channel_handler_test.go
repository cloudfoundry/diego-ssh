package handlers_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers/fake_handlers"
	"github.com/cloudfoundry-incubator/diego-ssh/handlers/fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	fake_server "github.com/cloudfoundry-incubator/diego-ssh/server/fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("DirectTcpipChannelHandler", func() {
	var (
		sshd   *daemon.Daemon
		client *ssh.Client

		logger          *lagertest.TestLogger
		serverSSHConfig *ssh.ServerConfig

		handler     *fake_handlers.FakeNewChannelHandler
		testHandler *handlers.DirectTcpipChannelHandler
		testDialer  *fakes.FakeDialer

		echoHandler *fake_server.FakeConnectionHandler
		echoServer  *server.Server
		echoAddress string
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		echoHandler = &fake_server.FakeConnectionHandler{}
		echoHandler.HandleConnectionStub = func(conn net.Conn) {
			io.Copy(conn, conn)
			conn.Close()
		}

		echoListener, err := net.Listen("tcp", "127.0.0.1:0")
		Ω(err).ShouldNot(HaveOccurred())
		echoAddress = echoListener.Addr().String()

		echoServer = server.NewServer(logger.Session("echo"), "", echoHandler)
		echoServer.SetListener(echoListener)
		go echoServer.Serve()

		serverSSHConfig = &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		testDialer = &fakes.FakeDialer{}
		testDialer.DialStub = net.Dial

		testHandler = handlers.NewDirectTcpipChannelHandler(testDialer)

		handler = &fake_handlers.FakeNewChannelHandler{}
		handler.HandleNewChannelStub = testHandler.HandleNewChannel

		newChannelHandlers := map[string]handlers.NewChannelHandler{
			"direct-tcpip": handler,
		}

		serverNetConn, clientNetConn := test_helpers.Pipe()

		sshd = daemon.New(logger, serverSSHConfig, nil, newChannelHandlers)
		go sshd.HandleConnection(serverNetConn)

		client = test_helpers.NewClient(clientNetConn, nil)
	})

	AfterEach(func() {
		client.Close()
		echoServer.Shutdown()
	})

	Context("when a session is opened", func() {
		var conn net.Conn

		JustBeforeEach(func() {
			var dialErr error
			conn, dialErr = client.Dial("tcp", echoAddress)
			Ω(dialErr).ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			conn.Close()
		})

		It("dials the the target from the remote end", func() {
			Ω(testDialer.DialCallCount()).Should(Equal(1))

			net, addr := testDialer.DialArgsForCall(0)
			Ω(net).Should(Equal("tcp"))
			Ω(addr).Should(Equal(echoAddress))
		})

		It("copies data between the local and target connections", func() {
			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			writer.WriteString("Hello, World!\n")
			writer.Flush()

			data, err := reader.ReadString('\n')
			Ω(err).ShouldNot(HaveOccurred())

			Ω(data).Should(Equal("Hello, World!\n"))
		})

		Describe("channel close coordination", func() {
			var completed chan struct{}

			BeforeEach(func() {
				completed = make(chan struct{}, 1)
				handler.HandleNewChannelStub = func(logger lager.Logger, newChannel ssh.NewChannel) {
					testHandler.HandleNewChannel(logger, newChannel)
					completed <- struct{}{}
				}
			})

			AfterEach(func() {
				close(completed)
			})

			Context("when the client connection closes", func() {
				It("the handler returns", func() {
					Consistently(completed).ShouldNot(Receive())
					conn.Close()
					Eventually(completed).Should(Receive())
				})
			})

			Context("when the target connection closes", func() {
				It("the handler returns", func() {
					Consistently(completed).ShouldNot(Receive())

					Ω(echoHandler.HandleConnectionCallCount()).Should(Equal(1))
					echoConn := echoHandler.HandleConnectionArgsForCall(0)
					echoConn.Close()

					Eventually(completed).Should(Receive())
				})
			})
		})
	})

	Context("when the direct-tcpip extra data fails to unmarshal", func() {
		It("rejects the open channel request", func() {
			_, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(struct{ Bogus int }{Bogus: 1234}))
			Ω(err).Should(Equal(&ssh.OpenChannelError{
				Reason:  ssh.ConnectionFailed,
				Message: "Failed to parse open channel message",
			}))
		})
	})

	Context("when dialing the target fails", func() {
		BeforeEach(func() {
			testDialer.DialStub = func(net, addr string) (net.Conn, error) {
				return nil, errors.New("woops")
			}
		})

		It("rejects the open channel request", func() {
			_, err := client.Dial("tcp", echoAddress)
			Ω(err).Should(Equal(&ssh.OpenChannelError{
				Reason:  ssh.ConnectionFailed,
				Message: "woops",
			}))
		})
	})

	Context("when an out of band request is sent across the channel", func() {
		type channelOpenDirectTcpipMsg struct {
			TargetAddr string
			TargetPort uint32
			OriginAddr string
			OriginPort uint32
		}
		var directTcpipMessage channelOpenDirectTcpipMsg

		BeforeEach(func() {
			addr, port, err := net.SplitHostPort(echoAddress)
			Ω(err).ShouldNot(HaveOccurred())

			p, err := strconv.ParseUint(port, 10, 16)
			Ω(err).ShouldNot(HaveOccurred())

			directTcpipMessage.TargetAddr = addr
			directTcpipMessage.TargetPort = uint32(p)
		})

		It("rejects the requests", func() {
			channel, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(directTcpipMessage))
			Ω(err).ShouldNot(HaveOccurred())

			accepted, err := channel.SendRequest("something", true, nil)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(accepted).Should(BeFalse())

			channel.Close()
		})
	})
})
