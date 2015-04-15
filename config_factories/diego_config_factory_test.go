package config_factories_test

import (
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/config_factories"
	"github.com/cloudfoundry-incubator/diego-ssh/daemon"
	"github.com/cloudfoundry-incubator/diego-ssh/proxy"
	"github.com/cloudfoundry-incubator/diego-ssh/server"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("DiegoConfigFactory", func() {
	var (
		logger      *lagertest.TestLogger
		factory     proxy.ConfigFactory
		permissions *ssh.Permissions

		clientConfig *ssh.ClientConfig
		address      string
		configErr    error
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		factory = config_factories.NewDiegoConfigFactory(logger, TestPrivateKey)

		permissions = &ssh.Permissions{
			CriticalOptions: map[string]string{
				"diego:container-address": "1.2.3.4",
				"diego:ssh-daemon-port":   "3333",
			},
		}
	})

	JustBeforeEach(func() {
		clientConfig, address, configErr = factory.Create(permissions)
	})

	It("returns the target address", func() {
		Ω(address).Should(Equal("1.2.3.4:3333"))
	})

	It("returns the ssh client config", func() {
		Ω(clientConfig).ShouldNot(BeNil())

		authenticator := authenticators.NewPublicKeyAuthenticator(TestPublicKey)
		serverConfig := &ssh.ServerConfig{
			PublicKeyCallback: authenticator.Authenticate,
		}
		serverConfig.AddHostKey(TestPrivateKey)

		sshd := daemon.New(logger, serverConfig, nil, nil)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Ω(err).ShouldNot(HaveOccurred())

		server := server.NewServer(logger, "", sshd)
		server.SetListener(listener)
		go server.Serve()

		client, err := ssh.Dial("tcp", listener.Addr().String(), clientConfig)
		Ω(err).ShouldNot(HaveOccurred())

		client.Close()
		server.Shutdown()
	})

	Context("when permissions is nil", func() {
		BeforeEach(func() {
			permissions = nil
		})

		It("fails the request with an error", func() {
			Ω(configErr).Should(HaveOccurred())
		})
	})
})
