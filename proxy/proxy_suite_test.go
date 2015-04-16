package proxy_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"testing"
)

var (
	TestHostKey    ssh.Signer
	TestPrivatePem string
	TestPublicPem  string
)

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}

var _ = BeforeSuite(func() {
	TestHostKey = test_helpers.GenerateRsaHostKey()

	privatePem, publicPem := test_helpers.GenerateRsaKeyPair()

	TestPrivatePem = string(privatePem)
	TestPublicPem = string(publicPem)
})
