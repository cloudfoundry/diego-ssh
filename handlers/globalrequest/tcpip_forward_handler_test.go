package globalrequest_test

import (
	"net"
	"sync"

	"golang.org/x/crypto/ssh"

	"code.cloudfoundry.org/diego-ssh/daemon"
	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/diego-ssh/handlers/globalrequest"
	"code.cloudfoundry.org/diego-ssh/test_helpers"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TCPIPForward Handler", func() {
	var (
		serverSSHConfig *ssh.ServerConfig
		sshd            *daemon.Daemon
		sshClient       *ssh.Client

		remoteAddress string

		logger *lagertest.TestLogger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("tcpip-forward-test")

		// Get unused port and close
		remoteListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		remoteAddress = remoteListener.Addr().String()
		remoteListener.Close()

		serverSSHConfig = &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		tcpipHandler := new(globalrequest.TCPIPForwardHandler)
		cancelTCPIPHandler := new(globalrequest.CancelTCPIPForwardHandler)

		globalRequestHandlers := map[string]handlers.GlobalRequestHandler{
			globalrequest.TCPIPForward:       tcpipHandler,
			globalrequest.CancelTCPIPForward: cancelTCPIPHandler,
		}

		serverNetConn, clientNetConn := test_helpers.Pipe()
		sshd = daemon.New(logger, serverSSHConfig, globalRequestHandlers, nil)

		go sshd.HandleConnection(serverNetConn)

		sshClient = test_helpers.NewClient(clientNetConn, nil)
	})

	// Charlie's rough idea of whats going...
	//
	// Remote: :8080
	// Forward to: localhost:123
	// Serve on: localhost:123
	// Curl: :8080 -> localhost:123
	//
	It("listens for multiple connections on the interface/port specified", func() {
		listener, err := sshClient.Listen("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())

		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		wg := new(sync.WaitGroup)
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				remoteConn, err := net.Dial("tcp", remoteAddress)
				Expect(err).NotTo(HaveOccurred())

				defer remoteConn.Close()

				expectedMsg := []byte("hello")
				resp := make([]byte, 5)
				_, err = remoteConn.Read(resp)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp).To(Equal(expectedMsg))
			}()
		}
		wg.Wait()
	})
	It("allows the requester to ask for connections to be forwarded from an unused port", func() {
		listener, err := sshClient.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())

		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		remoteAddr := listener.Addr().String()
		remoteConn, err := net.Dial("tcp", remoteAddr)
		Expect(err).NotTo(HaveOccurred())

		defer remoteConn.Close()

		expectedMsg := []byte("hello")
		resp := make([]byte, 5)
		_, err = remoteConn.Read(resp)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp).To(Equal(expectedMsg))
	})
	It("allows the requester to ask for connections to be forwarded from all interfaces", func() {
		listener, err := sshClient.Listen("tcp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())

		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		remoteAddr := listener.Addr().String()
		remoteConn, err := net.Dial("tcp", remoteAddr)
		Expect(err).NotTo(HaveOccurred())

		defer remoteConn.Close()

		expectedMsg := []byte("hello")
		resp := make([]byte, 5)
		_, err = remoteConn.Read(resp)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp).To(Equal(expectedMsg))
	})

	It("can listen again after cancelling the request", func() {
		listener, err := sshClient.Listen("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(listener.Close()).To(Succeed())

		listener, err = sshClient.Listen("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())

		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		remoteConn, err := net.Dial("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())

		defer remoteConn.Close()

		expectedMsg := []byte("hello")
		resp := make([]byte, 5)
		_, err = remoteConn.Read(resp)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp).To(Equal(expectedMsg))

	})
})

func ServeListener(ln net.Listener, logger lager.Logger) {
	defer GinkgoRecover()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("listener-failed-to-accept", err)
			return
		}
		n, err := conn.Write([]byte("hello"))
		conn.Close()
		if err != nil {
			logger.Error("server-sent-message-error", err)
			Expect(err).NotTo(HaveOccurred())
		} else {
			logger.Info("server-sent-message-success", lager.Data{"bytes-sent": n})
		}
	}
}
