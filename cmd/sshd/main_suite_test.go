package main_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

var sshdPath string
var sshdPort int

func TestSSHDaemon(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sshd Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	sshd, err := gexec.Build("github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd", "-race")
	Ω(err).ShouldNot(HaveOccurred())

	payload, err := json.Marshal(map[string]string{
		"sshd": sshd,
	})
	Ω(err).ShouldNot(HaveOccurred())

	return payload
}, func(payload []byte) {
	binaries := map[string]string{}

	err := json.Unmarshal(payload, &binaries)
	Ω(err).ShouldNot(HaveOccurred())

	sshdPort = 7001 + GinkgoParallelNode()
	sshdPath = string(binaries["sshd"])
})

var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})
