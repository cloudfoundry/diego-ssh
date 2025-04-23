package helpers_test

import (
	"unicode/utf8"

	"code.cloudfoundry.org/diego-ssh/helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"
)

const (
	TestPrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAx0y65jB977anY39jzB7AkojdAyqiADG4BTcXmKIy7w/GY/bi
Aq/AcO/SVAsq1iJ+SAmiQXt1K6kL8wUGtxlB1D+Ze0d0jw05Ep+O5rRF1dMDFUsA
0yrgfsUfryl7XOl9LmE1PKLinKExooZrfJTSqW1oRjHpIWZMtJj25glDtrfz+Wyd
6wPYH1CgOdQjSAORWYrhb9xYPzIxG5XMeMyO5xtL3sLEsdM1iROIl9rOu1qem1n+
Xs/z+03tpIoQc4gjVvbykYdZQ5mvCgbxtPRVy7EmYSbQflmMu3TWZmT20ZWDCHzl
3eDdFMOpqRaRFg/TjlNjH20TQbruKumk7ldogQIDAQABAoIBABujCEfjcZNMQOoL
QEuN+CZZ1EwcHVrpihsvCJah524/QcOa+LxmoskGeKQu6EHJhrl2nIl4FUd4qa+J
guThG7/TEfWGcyNjMgbjGW3kkcqU+Fh7jiG6UGdD7qDbn7/CoRlNYZSHAeW2dKuU
+FLOUGguQ8d4JFv9U6W3kIVVw44StVMkQwh0TB9kh7yzeHrpVddaMPzVZUmCWm2Y
NPN5EZq96DmmcEQC7Gktj7kPgC5UWcc8wF2Xy74sZb3RKOeyc5e7ddMDLbNI5STr
iRT3Fg+bhWQhhMUQfvD9KSh/9IK0OGu/3SSb9WeEzMUdh5mho1IsERugaXsVlne8
6JWW7gECgYEAzTTSJDRm8CiBSa4sn5KzLOHvn3YfSC91aERjrbZuVDdmVMJvhpLw
JW6/5zmz7X7Hr3mwHBSj+rS4/rIoEVvTjWrJm6GUSXXPwRwoJedbK67FU0MxBMzt
iqi+qBHdsKRhdrlM3W9RryGkcS1AkK+6B2Feu3GVGUQDz6G/yaTJ8UcCgYEA+KGh
D+PtdAd3s1sdAJlRuS4kCXCLbO/5EWfMMHVaewebpGs8bZnW4cpFaGR7zXd9Emkk
QuZWE7L44SNQrirECtGcu3zEKx1grYo+2jYoLYexiwOf6UEMWJEExLS475EDgmUJ
7Fy5tt2mwwV2GBXZfTHuQLOo9Zxjsf3NAKAZ+/cCgYBV+nKtrrMOnroE6BBUT7/4
5zViJ7jVouTbagQlrZEuggPDMbBOv1QVKwEG3Ztwv7Tk5eSO72sBSSVVucml9EaA
MyUDq0CZQt5oN+bucrA1bkXJLBbmvwIsHaW8f7fWIhmgB+WXxeOAsGTY8q/hr28P
VpG9kcp5ypCaN1hHIV9nUwKBgQDKcUBlYd8MJLBwV3XL8Qq7zzgEf6Dm+JZCd9Oo
eUVM+6rdO3ueei6e9kWBdJ/hcrNh9D5UQpw/ufAv0MN2rNenP3lwp2xK9sarRu9a
WdJpEB2d5TulfxOAYcQSLlyOo/LJj19/FxkYLm4ESUQY5GGMMMWf5Sljow0B9nef
VL0TjQKBgG9/w5XpX7K8nnUVGgYuEhbBj7lel2Ad7wjqwxuqDxi3jqVvuIR7VYeg
feuxbZkmphtEOKtaVDSWxGbNXbuN8H9eQqsGhK1Xcn/FxKVu7k+9GYyqeOwhjaqy
HbXzxBM4Ki0l1kaUjDVKjz3fsIq9Pl/lBoKYAmDvkK4xoxcs05ws
-----END RSA PRIVATE KEY-----`

	ExpectedSHA256Fingerprint = `c7:e1:1c:47:3b:7b:11:f5:6e:5d:3c:67:16:dd:35:96:4c:5a:6c:f5:0b:82:e5:20:a6:f7:29:a3:9d:bf:3e:e7`
)

var _ = Describe("Fingerprint", func() {
	var publicKey ssh.PublicKey
	var fingerprint string

	BeforeEach(func() {
		privateKey, err := ssh.ParsePrivateKey([]byte(TestPrivateKeyPem))
		Expect(err).NotTo(HaveOccurred())

		publicKey = privateKey.PublicKey()
	})

	Describe("SHA256 Fingerprint", func() {
		BeforeEach(func() {
			fingerprint = helpers.SHA256Fingerprint(publicKey)
		})

		It("should have the correct length", func() {
			Expect(utf8.RuneCountInString(fingerprint)).To(Equal(helpers.SHA256_FINGERPRINT_LENGTH))
		})

		It("should match the expected fingerprint", func() {
			Expect(fingerprint).To(Equal(ExpectedSHA256Fingerprint))
		})
	})
})
