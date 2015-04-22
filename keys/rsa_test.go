package keys_test

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/keys"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RSA", func() {
	var keyPair keys.KeyPair
	var bits int

	BeforeEach(func() {
		bits = 1024
	})

	JustBeforeEach(func() {
		var err error
		keyPair, err = keys.RSAKeyPairFactory.NewKeyPair(bits)
		Ω(err).ShouldNot(HaveOccurred())
	})

	Describe("PrivateKey", func() {
		It("returns the ssh private key associted with the public key", func() {
			Ω(keyPair.PrivateKey()).ShouldNot(BeNil())
			Ω(keyPair.PrivateKey().PublicKey()).Should(Equal(keyPair.PublicKey()))
		})

		Context("when creating a 1024 bit key", func() {
			BeforeEach(func() {
				bits = 1024
			})

			It("the private key is 1024 bits", func() {
				block, _ := pem.Decode([]byte(keyPair.PEMEncodedPrivateKey()))
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(key.N.BitLen()).Should(Equal(1024))
			})
		})

		Context("when creating a 2048 bit key", func() {
			BeforeEach(func() {
				bits = 2048
			})

			It("the private key is 2048 bits", func() {
				block, _ := pem.Decode([]byte(keyPair.PEMEncodedPrivateKey()))
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(key.N.BitLen()).Should(Equal(2048))
			})
		})
	})

	Describe("PEMEncodedPrivateKey", func() {
		It("correctly represents the private key", func() {
			privateKey, err := ssh.ParsePrivateKey([]byte(keyPair.PEMEncodedPrivateKey()))
			Ω(err).ShouldNot(HaveOccurred())

			Ω(privateKey.PublicKey().Marshal()).Should(Equal(keyPair.PublicKey().Marshal()))
		})
	})

	Describe("PublicKey", func() {
		It("equals the public key associated with the private key", func() {
			Ω(keyPair.PrivateKey().PublicKey().Marshal()).Should(Equal(keyPair.PublicKey().Marshal()))
		})
	})

	Describe("Fingerprint", func() {
		It("equals the MD5 fingerprint of the public key", func() {
			expectedFingerprint := helpers.MD5Fingerprint(keyPair.PublicKey())

			Ω(keyPair.Fingerprint()).Should(Equal(expectedFingerprint))
		})
	})

	Describe("AuthorizedKey", func() {
		It("equals the authorized key formatted public key", func() {
			expectedAuthorizedKey := string(ssh.MarshalAuthorizedKey(keyPair.PublicKey()))

			Ω(keyPair.AuthorizedKey()).Should(Equal(expectedAuthorizedKey))
		})
	})
})
