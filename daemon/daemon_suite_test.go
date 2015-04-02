package daemon_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"testing"
)

var TestHostKey ssh.Signer

func TestDaemon(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Daemon Suite")
}

var _ = BeforeSuite(func() {
	TestHostKey = GenerateRsaHostKey()
})

func GenerateRsaHostKey() ssh.Signer {
	generatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Ω(err).ShouldNot(HaveOccurred())

	encoded := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(generatedKey),
	})

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
