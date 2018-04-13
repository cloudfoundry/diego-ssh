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
		remoteAddress string
		sshClient     *ssh.Client
		logger        *lagertest.TestLogger
	)

	randomUnusedAddress := func() string {
		remoteListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		addr := remoteListener.Addr().String()
		remoteListener.Close()
		return addr
	}

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("tcpip-forward-test")

		remoteAddress = randomUnusedAddress()

		globalRequestHandlers := map[string]handlers.GlobalRequestHandler{
			globalrequest.TCPIPForward:       new(globalrequest.TCPIPForwardHandler),
			globalrequest.CancelTCPIPForward: new(globalrequest.CancelTCPIPForwardHandler),
		}

		serverSSHConfig := &ssh.ServerConfig{
			NoClientAuth: true,
		}
		serverSSHConfig.AddHostKey(TestHostKey)

		sshd := daemon.New(logger, serverSSHConfig, globalRequestHandlers, nil)

		serverNetConn, clientNetConn := test_helpers.Pipe()
		go sshd.HandleConnection(serverNetConn)
		sshClient = test_helpers.NewClient(clientNetConn, nil)
	})

	testTCPIPForward := func(remoteAddr string) {
		remoteConn, err := net.Dial("tcp", remoteAddr)
		Expect(err).NotTo(HaveOccurred())

		defer remoteConn.Close()

		expectedMsg := []byte("hello")
		resp := make([]byte, 5)
		_, err = remoteConn.Read(resp)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp).To(Equal(expectedMsg))
	}

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
				testTCPIPForward(remoteAddress)
			}()
		}
		wg.Wait()
	})

	It("allows the requester to ask for connections to be forwarded from an unused port", func() {
		listener, err := sshClient.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		testTCPIPForward(listener.Addr().String())
	})

	It("allows the requester to ask for connections to be forwarded from all interfaces", func() {
		listener, err := sshClient.Listen("tcp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		testTCPIPForward(listener.Addr().String())
	})

	It("can listen again after cancelling the request", func() {
		listener, err := sshClient.Listen("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(listener.Close()).To(Succeed())

		listener, err = sshClient.Listen("tcp", remoteAddress)
		Expect(err).NotTo(HaveOccurred())

		defer listener.Close()
		go ServeListener(listener, logger.Session("local"))

		testTCPIPForward(remoteAddress)
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
		}
		logger.Info("server-sent-message-success", lager.Data{"bytes-sent": n})
	}
}
