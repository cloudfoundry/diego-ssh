package test_helpers

import (
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"
)

func GenerateRsaHostKey() ssh.Signer {
	encoded, err := helpers.GeneratePemEncodedRsaKey()
	Ω(err).ShouldNot(HaveOccurred())

	privateKey, err := ssh.ParsePrivateKey(encoded)
	Ω(err).ShouldNot(HaveOccurred())

	return privateKey
}

func GenerateDsaHostKey() ssh.Signer {
	encoded, err := helpers.GeneratePemEncodedDsaKey()
	Ω(err).ShouldNot(HaveOccurred())

	privateKey, err := ssh.ParsePrivateKey(encoded)
	Ω(err).ShouldNot(HaveOccurred())

	return privateKey
}

func Pipe() (net.Conn, net.Conn) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	Ω(err).ShouldNot(HaveOccurred())

	address := listener.Addr().String()

	serverConnCh := make(chan net.Conn, 1)
	go func(serverConnCh chan net.Conn, listener net.Listener) {
		defer GinkgoRecover()
		conn, err := listener.Accept()
		Ω(err).ShouldNot(HaveOccurred())

		serverConnCh <- conn
	}(serverConnCh, listener)

	clientConn, err := net.Dial("tcp", address)
	Ω(err).ShouldNot(HaveOccurred())

	return <-serverConnCh, clientConn
}

func NewClient(clientNetConn net.Conn, clientConfig *ssh.ClientConfig) *ssh.Client {
	if clientConfig == nil {
		clientConfig = &ssh.ClientConfig{
			User: "username",
			Auth: []ssh.AuthMethod{
				ssh.Password("secret"),
			},
		}
	}

	clientConn, clientChannels, clientRequests, clientConnErr := ssh.NewClientConn(clientNetConn, "0.0.0.0", clientConfig)
	Ω(clientConnErr).ShouldNot(HaveOccurred())

	return ssh.NewClient(clientConn, clientChannels, clientRequests)
}
