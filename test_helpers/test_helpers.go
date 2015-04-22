package test_helpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"
)

func GenerateRsaHostKey() ssh.Signer {
	encoded, err := helpers.GeneratePemEncodedRsaKey(1024)
	Ω(err).ShouldNot(HaveOccurred())

	privateKey, err := ssh.ParsePrivateKey(encoded)
	Ω(err).ShouldNot(HaveOccurred())

	return privateKey
}

func SSHKeyGen() ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	Ω(err).ShouldNot(HaveOccurred())

	err = privateKey.Validate()
	Ω(err).ShouldNot(HaveOccurred())

	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privatePem := pem.EncodeToMemory(&privateBlock)

	sshPublicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	Ω(err).ShouldNot(HaveOccurred())

	return privatePem, ssh.MarshalAuthorizedKey(sshPublicKey)
}

func DecodePem(data []byte) []byte {
	block, _ := pem.Decode([]byte(data))
	Ω(block).ShouldNot(BeNil())

	return block.Bytes
}

func GenerateSshKeyPair() (ssh.Signer, ssh.PublicKey) {
	privatePem, publicAuthorizedKey := SSHKeyGen()

	privateKey, err := ssh.ParsePrivateKey(privatePem)
	Ω(err).ShouldNot(HaveOccurred())

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicAuthorizedKey)
	Ω(err).ShouldNot(HaveOccurred())

	return privateKey, publicKey
}

func WaitFor(f func() error) error {
	ch := make(chan error)
	go func() {
		err := f()
		ch <- err
	}()
	var err error
	Eventually(ch, 10).Should(Receive(&err))
	return err
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
