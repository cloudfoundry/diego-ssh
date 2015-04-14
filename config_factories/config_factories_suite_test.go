package config_factories_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"testing"
)

var TestPublicKey ssh.PublicKey
var TestPrivateKey ssh.Signer

func TestConfigFactories(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ConfigFactories Suite")
}

var _ = BeforeSuite(func() {
	TestPrivateKey, TestPublicKey = test_helpers.GenerateSshKeyPair()
})
