package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"

	"testing"
	"time"

	"code.cloudfoundry.org/consuladapter/consulrunner"
	"code.cloudfoundry.org/diego-ssh/cmd/sshd/testrunner"
	"code.cloudfoundry.org/diego-ssh/keys"
	"code.cloudfoundry.org/inigo/helpers/portauthority"
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

	sshdPort             uint16
	sshdTLSPort          uint16
	sshdContainerPort    uint16
	sshdContainerTLSPort uint16
	sshProxyPort         uint16
	healthCheckProxyPort uint16

	sshdAddress string

	hostKeyPem          string
	privateKeyPem       string
	publicAuthorizedKey string
	consulRunner        *consulrunner.ClusterRunner

	fixturesPath   string
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string

	portAllocator portauthority.PortAllocator
)

func TestSSHProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SSH Proxy Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	fixturesPath = path.Join(os.Getenv("GOPATH"), "src/code.cloudfoundry.org/diego-ssh/cmd/ssh-proxy/fixtures")

	caFile = path.Join(fixturesPath, "green-certs", "server-ca.crt")
	serverCertFile = path.Join(fixturesPath, "green-certs", "server.crt")
	serverKeyFile = path.Join(fixturesPath, "green-certs", "server.key")
	clientCertFile = path.Join(fixturesPath, "green-certs", "client.crt")
	clientKeyFile = path.Join(fixturesPath, "green-certs", "client.key")

	sshProxy, err := gexec.Build("code.cloudfoundry.org/diego-ssh/cmd/ssh-proxy", "-race")
	Expect(err).NotTo(HaveOccurred())

	sshd, err := gexec.Build("code.cloudfoundry.org/diego-ssh/cmd/sshd", "-race")
	Expect(err).NotTo(HaveOccurred())

	hostKey, err := keys.RSAKeyPairFactory.NewKeyPair(1024)
	Expect(err).NotTo(HaveOccurred())

	privateKey, err := keys.RSAKeyPairFactory.NewKeyPair(1024)
	Expect(err).NotTo(HaveOccurred())

	payload, err := json.Marshal(map[string]string{
		"ssh-proxy":      sshProxy,
		"sshd":           sshd,
		"host-key":       hostKey.PEMEncodedPrivateKey(),
		"private-key":    privateKey.PEMEncodedPrivateKey(),
		"authorized-key": privateKey.AuthorizedKey(),

		"fixturesPath": fixturesPath,

		"caFile":         caFile,
		"serverCertFile": serverCertFile,
		"serverKeyFile":  serverKeyFile,
		"clientCertFile": clientCertFile,
		"clientKeyFile":  clientKeyFile,
	})

	Expect(err).NotTo(HaveOccurred())

	return payload
}, func(payload []byte) {
	context := map[string]string{}

	err := json.Unmarshal(payload, &context)
	Expect(err).NotTo(HaveOccurred())

	fixturesPath = context["fixturesPath"]

	caFile = context["caFile"]
	serverCertFile = context["serverCertFile"]
	serverKeyFile = context["serverKeyFile"]
	clientCertFile = context["clientCertFile"]
	clientKeyFile = context["clientKeyFile"]

	hostKeyPem = context["host-key"]
	privateKeyPem = context["private-key"]
	publicAuthorizedKey = context["authorized-key"]

	node := GinkgoParallelNode()
	startPort := 1050 * node
	portRange := 1000
	endPort := startPort + portRange

	portAllocator, err = portauthority.New(startPort, endPort)
	Expect(err).NotTo(HaveOccurred())

	sshdPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())

	sshdContainerPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())
	sshdPath = context["sshd"]

	sshdTLSPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())

	sshdContainerTLSPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())
	sshdPath = context["sshd"]

	sshProxyPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())
	sshProxyPath = context["ssh-proxy"]

	healthCheckProxyPort, err = portAllocator.ClaimPorts(1)
	Expect(err).NotTo(HaveOccurred())

	consulPort, err := portAllocator.ClaimPorts(consulrunner.PortOffsetLength)
	Expect(err).NotTo(HaveOccurred())
	consulRunner = consulrunner.NewClusterRunner(
		consulrunner.ClusterRunnerConfig{
			StartingPort: int(consulPort),
			NumNodes:     1,
			Scheme:       "http",
		},
	)

	consulRunner.Start()
	consulRunner.WaitUntilReady()
})

var _ = BeforeEach(func() {

	if runtime.GOOS == "windows" {
		Skip("SSH not supported on Windows, and SSH proxy never runs on Windows anyway")
	}

	err := consulRunner.Reset()
	Expect(err).NotTo(HaveOccurred())

	sshdAddress = fmt.Sprintf("127.0.0.1:%d", sshdPort)
	sshdArgs := testrunner.Args{
		Address:       sshdAddress,
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
	consulRunner.Stop()
}, func() {
	gexec.CleanupBuildArtifacts()
})
