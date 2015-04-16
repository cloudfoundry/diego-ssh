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
	var encodedRsaKey []byte
	var encodedDsaKey []byte

	BeforeSuite(func() {
		var err error
		encodedDsaKey, err = helpers.GeneratePemEncodedDsaKey()
		Ω(err).ShouldNot(HaveOccurred())

		encodedRsaKey, err = helpers.GeneratePemEncodedRsaKey()
		Ω(err).ShouldNot(HaveOccurred())
	})

	Describe("GeneratePemEncodedRsaKey", func() {
		It("generates a RSA PRIVATE KEY block", func() {
			Ω(encodedRsaKey).Should(ContainSubstring("--BEGIN RSA PRIVATE KEY--"))
			Ω(encodedRsaKey).Should(ContainSubstring("--END RSA PRIVATE KEY--"))
		})

		It("is 2048 bits in length", func() {
			block, _ := pem.Decode(encodedRsaKey)
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			Ω(err).ShouldNot(HaveOccurred())

			Ω(key.N.BitLen()).Should(Equal(2048))
		})

		It("can be used ass an ssh.Signer", func() {
			signer, err := ssh.ParsePrivateKey(encodedRsaKey)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(signer).ShouldNot(BeNil())
		})
	})

	Describe("GeneratePemEncodedDsaKey", func() {
		It("generates a DSA PRIVATE KEY block", func() {
			Ω(encodedDsaKey).Should(ContainSubstring("--BEGIN DSA PRIVATE KEY--"))
			Ω(encodedDsaKey).Should(ContainSubstring("--END DSA PRIVATE KEY--"))
		})

		It("is 2048 bits in length", func() {
			block, _ := pem.Decode(encodedDsaKey)
			key, err := ssh.ParseDSAPrivateKey(block.Bytes)
			Ω(err).ShouldNot(HaveOccurred())

			Ω(key.P.BitLen()).Should(Equal(2048))
			Ω(key.Q.BitLen()).Should(Equal(256))
		})

		It("can be used ass an ssh.Signer", func() {
			signer, err := ssh.ParsePrivateKey(encodedDsaKey)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(signer).ShouldNot(BeNil())
		})
	})
})
