package main_test

import (
	"encoding/json"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

var (
	sshdPath string

	sshdPort            int
	hostKeyPem          string
	privateKeyPem       string
	publicAuthorizedKey string
)

func TestSSHDaemon(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sshd Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	sshd, err := gexec.Build("github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd", "-race")
	Ω(err).ShouldNot(HaveOccurred())

	hostKeyPem, err := helpers.GeneratePemEncodedRsaKey(1024)
	Ω(err).ShouldNot(HaveOccurred())

	privatePem, authorizedKey := test_helpers.SSHKeyGen()

	payload, err := json.Marshal(map[string]string{
		"sshd":           sshd,
		"host-key":       string(hostKeyPem),
		"private-key":    string(privatePem),
		"authorized-key": string(authorizedKey),
	})

	Ω(err).ShouldNot(HaveOccurred())

	return payload
}, func(payload []byte) {
	context := map[string]string{}

	err := json.Unmarshal(payload, &context)
	Ω(err).ShouldNot(HaveOccurred())

	hostKeyPem = context["host-key"]
	privateKeyPem = context["private-key"]
	publicAuthorizedKey = context["authorized-key"]

	sshdPort = 7001 + GinkgoParallelNode()
	sshdPath = context["sshd"]
})

var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})
