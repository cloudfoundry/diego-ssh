package main_test

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SSH daemon", func() {

	var (
		runner       ifrit.Runner
		process      ifrit.Process
		exitDuration = 3 * time.Second

		address string
		hostKey []byte
	)

	startSSHDaemon := func() *ginkgomon.Runner {
		runner := ginkgomon.New(ginkgomon.Config{
			Name:          "sshd",
			AnsiColorCode: "1;96m",
			StartCheck:    "sshd.started",
			Command: exec.Command(
				sshdPath,
				"-address", address,
				"-hostKey", string(hostKey),
				"-allowUnauthenticatedClients",
			),
		})

		return runner
	}

	BeforeEach(func() {
		var err error
		hostKey, err = helpers.GeneratePemEncodedRsaKey()
		Ω(err).ShouldNot(HaveOccurred())

		address = fmt.Sprintf("127.0.0.1:%d", sshdPort)

		runner = startSSHDaemon()
		process = ginkgomon.Invoke(runner)
		Ω(process).ShouldNot(BeNil())
	})

	AfterEach(func() {
		ginkgomon.Interrupt(process, exitDuration)
	})

	It("starts the daemon", func() {
		Ω(process).ShouldNot(BeNil())
	})

	Context("when a client connects", func() {
		var client *ssh.Client
		var dialErr error

		BeforeEach(func() {
			client, dialErr = ssh.Dial("tcp", address, &ssh.ClientConfig{})
		})

		It("completes a handshake", func() {
			Ω(dialErr).ShouldNot(HaveOccurred())
			Ω(client).ShouldNot(BeNil())
		})

		It("can execute commands", func() {
			session, err := client.NewSession()
			Ω(err).ShouldNot(HaveOccurred())

			result, err := session.Output("echo -n 'Hello there!'")
			Ω(err).ShouldNot(HaveOccurred())

			Ω(string(result)).Should(Equal("Hello there!"))
		})
	})
})
