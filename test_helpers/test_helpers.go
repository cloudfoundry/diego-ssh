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

func GenerateRsaKeyPair() ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Ω(err).ShouldNot(HaveOccurred())

	err = privateKey.Validate()
	Ω(err).ShouldNot(HaveOccurred())

	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privatePem := pem.EncodeToMemory(&privateBlock)

	publicEncoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	Ω(err).ShouldNot(HaveOccurred())

	pub_blk := pem.Block{
		Type:    "PUBLIC RSA KEY",
		Headers: nil,
		Bytes:   publicEncoded,
	}
	publicPem := pem.EncodeToMemory(&pub_blk)

	return privatePem, publicPem
}

func DecodePem(data []byte) []byte {
	block, _ := pem.Decode([]byte(data))
	Ω(block).ShouldNot(BeNil())

	return block.Bytes
}

func GenerateSshKeyPair() (ssh.Signer, ssh.PublicKey) {
	privatePem, publicPem := GenerateRsaKeyPair()

	privateKey, err := ssh.ParsePrivateKey(privatePem)
	Ω(err).ShouldNot(HaveOccurred())

	publicKey := ParsePublicKeyPem(publicPem)

	return privateKey, publicKey
}

func ParsePublicKeyPem(data []byte) ssh.PublicKey {
	x509PublicKey, err := x509.ParsePKIXPublicKey(DecodePem(data))
	Ω(err).ShouldNot(HaveOccurred())

	publicKey, err := ssh.NewPublicKey(x509PublicKey)
	Ω(err).ShouldNot(HaveOccurred())

	return publicKey
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
