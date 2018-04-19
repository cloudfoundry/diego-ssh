package globalrequest_test

import (
	"fmt"
	"net"

	"code.cloudfoundry.org/diego-ssh/daemon"
	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/diego-ssh/handlers/globalrequest"
	"code.cloudfoundry.org/diego-ssh/handlers/globalrequest/internal"
	"code.cloudfoundry.org/diego-ssh/test_helpers"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/localip"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CancelTcpipForwardHandler", func() {
	var (
		remoteAddress string
		sshClient     *ssh.Client
		logger        *lagertest.TestLogger
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("tcpip-forward-test")

		remotePort, err := localip.LocalPort()
		Expect(err).NotTo(HaveOccurred())
		remoteAddress = fmt.Sprintf("127.0.0.1:%d", remotePort)

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

	Context("when the request is invalid", func() {
		It("rejects the request", func() {
			payload := ssh.Marshal(struct {
				port uint16
			}{
				port: 10,
			})
			ok, _, err := sshClient.SendRequest("cancel-tcpip-forward", true, payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).NotTo(BeTrue())
		})
	})

	Context("when the listener isn't found", func() {
		It("rejects the request", func() {
			payload := ssh.Marshal(internal.TCPIPForwardRequest{
				Address: "127.0.0.1",
				Port:    9090,
			})
			ok, _, err := sshClient.SendRequest("cancel-tcpip-forward", true, payload)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).NotTo(BeTrue())
		})
	})

	Context("when the listener exists", func() {
		var (
			ok  bool
			err error
		)

		BeforeEach(func() {
			addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9090")
			Expect(err).NotTo(HaveOccurred())
			_, err = sshClient.ListenTCP(addr)
			Expect(err).NotTo(HaveOccurred())

			_, err = net.Dial("tcp", "127.0.0.1:9090")
			Expect(err).NotTo(HaveOccurred())

			payload := ssh.Marshal(internal.TCPIPForwardRequest{
				Address: "127.0.0.1",
				Port:    9090,
			})
			ok, _, err = sshClient.SendRequest("cancel-tcpip-forward", true, payload)
		})

		It("successfully process the request", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("stops listening to the port", func() {
			_, err := net.Dial("tcp", "127.0.0.1:9090")
			Expect(err).To(MatchError(ContainSubstring("connection refused")))
		})
	})
})
