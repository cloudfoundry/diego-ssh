package main_test

import (
	"encoding/json"
	"fmt"

	"testing"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd/testrunner"
	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

var (
	sshProxyPath string
	sshdPath     string
	sshdProcess  ifrit.Process

	sshdPort     int
	sshProxyPort int

	hostKeyPem        string
	privateUserKeyPem string
	publicUserKeyPem  string
)

func TestSSHProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SSH Proxy Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	sshProxy, err := gexec.Build("github.com/cloudfoundry-incubator/diego-ssh/cmd/ssh-proxy", "-race")
	Ω(err).ShouldNot(HaveOccurred())

	sshd, err := gexec.Build("github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd", "-race")
	Ω(err).ShouldNot(HaveOccurred())

	hostKeyPem, err := helpers.GeneratePemEncodedRsaKey()
	Ω(err).ShouldNot(HaveOccurred())

	privateUserKeyPem, publicUserKeyPem := test_helpers.GenerateRsaKeyPair()

	payload, err := json.Marshal(map[string]string{
		"ssh-proxy":        sshProxy,
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

	sshdPort = 7000 + GinkgoParallelNode()
	sshdPath = context["sshd"]

	sshProxyPort = 7100 + GinkgoParallelNode()
	sshProxyPath = context["ssh-proxy"]
})

var _ = BeforeEach(func() {
	sshdArgs := testrunner.Args{
		Address:       fmt.Sprintf("127.0.0.1:%d", sshdPort),
		HostKey:       hostKeyPem,
		PublicUserKey: publicUserKeyPem,
	}

	runner := testrunner.New(sshdPath, sshdArgs)
	sshdProcess = ifrit.Invoke(runner)
})

var _ = AfterEach(func() {
	ginkgomon.Kill(sshdProcess, 5*time.Second)
})

var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})
