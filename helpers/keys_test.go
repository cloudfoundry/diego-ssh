package helpers_test

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("Keys", func() {
	Describe("GeneratePemEncodedRsaKey", func() {
		var encodedRsaKey []byte
		var bits int

		BeforeEach(func() {
			bits = 1024
		})

		JustBeforeEach(func() {
			var err error
			encodedRsaKey, err = helpers.GeneratePemEncodedRsaKey(bits)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("generates a RSA PRIVATE KEY block", func() {
			Ω(encodedRsaKey).Should(ContainSubstring("--BEGIN RSA PRIVATE KEY--"))
			Ω(encodedRsaKey).Should(ContainSubstring("--END RSA PRIVATE KEY--"))
		})

		Context("when generating a key with 1024 bits", func() {
			BeforeEach(func() {
				bits = 1024
			})

			It("is 1024 bits in length", func() {
				block, _ := pem.Decode(encodedRsaKey)
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(key.N.BitLen()).Should(Equal(1024))
			})
		})

		Context("when generating a key with 2048 bits", func() {
			BeforeEach(func() {
				bits = 2048
			})

			It("is 2048 bits in length", func() {
				block, _ := pem.Decode(encodedRsaKey)
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				Ω(err).ShouldNot(HaveOccurred())

				Ω(key.N.BitLen()).Should(Equal(2048))
			})
		})

		It("can be used ass an ssh.Signer", func() {
			signer, err := ssh.ParsePrivateKey(encodedRsaKey)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(signer).ShouldNot(BeNil())
		})
	})
})
