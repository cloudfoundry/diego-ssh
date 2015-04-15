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

	sshdPort          int
	hostKeyPem        string
	privateUserKeyPem string
	publicUserKeyPem  string
)

func TestSSHDaemon(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sshd Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	sshd, err := gexec.Build("github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd", "-race")
	Ω(err).ShouldNot(HaveOccurred())

	hostKeyPem, err := helpers.GeneratePemEncodedRsaKey()
	Ω(err).ShouldNot(HaveOccurred())

	privateUserKeyPem, publicUserKeyPem := test_helpers.GenerateRsaKeyPair()

	payload, err := json.Marshal(map[string]string{
		"sshd":             sshd,
		"host-key":         string(hostKeyPem),
		"user-private-key": string(privateUserKeyPem),
		"user-public-key":  string(publicUserKeyPem),
	})

	Ω(err).ShouldNot(HaveOccurred())

	return payload
}, func(payload []byte) {
	context := map[string]string{}

	err := json.Unmarshal(payload, &context)
	Ω(err).ShouldNot(HaveOccurred())

	hostKeyPem = context["host-key"]
	privateUserKeyPem = context["user-private-key"]
	publicUserKeyPem = context["user-public-key"]

	sshdPort = 7001 + GinkgoParallelNode()
	sshdPath = context["sshd"]
})

var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})
