package authenticators_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PublicKeyAuthenticator", func() {
	var (
		privateKey ssh.Signer
		publicKey  ssh.PublicKey

		authenticator authenticators.PublicKeyAuthenticator

		metadata  *fake_ssh.FakeConnMetadata
		clientKey ssh.PublicKey

		permissions *ssh.Permissions
		authnError  error
	)

	BeforeEach(func() {
		privateKey, publicKey = test_helpers.GenerateSshKeyPair()
		authenticator = authenticators.NewPublicKeyAuthenticator(publicKey)

		metadata = &fake_ssh.FakeConnMetadata{}
		clientKey = publicKey
	})

	JustBeforeEach(func() {
		permissions, authnError = authenticator.Authenticate(metadata, clientKey)
	})

	It("creates an authenticator", func() {
		Ω(authenticator).ShouldNot(BeNil())
		Ω(authenticator.PublicKey()).Should(Equal(publicKey))
	})

	Describe("Authenticate", func() {
		BeforeEach(func() {
			clientKey = publicKey
		})

		Context("when the public key matches", func() {
			It("does not return an error", func() {
				Ω(authnError).ShouldNot(HaveOccurred())
				Ω(permissions).ShouldNot(BeNil())
			})
		})

		Context("when the public key does not match", func() {
			BeforeEach(func() {
				fakeKey := &fake_ssh.FakePublicKey{}
				fakeKey.MarshalReturns([]byte("go-away-alice"))
				clientKey = fakeKey
			})

			It("fails the authentication", func() {
				Ω(authnError).Should(HaveOccurred())
				Ω(permissions).Should(BeNil())
			})
		})
	})
})
