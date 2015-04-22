package main_test

import (
	"encoding/json"
	"fmt"

	"testing"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd/testrunner"
	"github.com/cloudfoundry-incubator/diego-ssh/keys"
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

	hostKeyPem          string
	privateKeyPem       string
	publicAuthorizedKey string
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

	hostKey, err := keys.RSAKeyPairFactory.NewKeyPair(1024)
	Ω(err).ShouldNot(HaveOccurred())

	privateKey, err := keys.RSAKeyPairFactory.NewKeyPair(1024)
	Ω(err).ShouldNot(HaveOccurred())

	payload, err := json.Marshal(map[string]string{
		"ssh-proxy":      sshProxy,
		"sshd":           sshd,
		"host-key":       hostKey.PEMEncodedPrivateKey(),
		"private-key":    privateKey.PEMEncodedPrivateKey(),
		"authorized-key": privateKey.AuthorizedKey(),
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

	sshdPort = 7000 + GinkgoParallelNode()
	sshdPath = context["sshd"]

	sshProxyPort = 7100 + GinkgoParallelNode()
	sshProxyPath = context["ssh-proxy"]
})

var _ = BeforeEach(func() {
	sshdArgs := testrunner.Args{
		Address:       fmt.Sprintf("127.0.0.1:%d", sshdPort),
		HostKey:       hostKeyPem,
		AuthorizedKey: publicAuthorizedKey,
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
