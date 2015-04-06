package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("SSH daemon", func() {
	var (
		runner       ifrit.Runner
		process      ifrit.Process
		exitDuration = 3 * time.Second

		address                     string
		hostKey                     []byte
		privateUserKey              []byte
		publicUserKey               []byte
		allowUnauthenticatedClients bool
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
				"-publicUserKey", string(publicUserKey),
				fmt.Sprintf("-allowUnauthenticatedClients=%t", allowUnauthenticatedClients),
			),
		})

		return runner
	}

	BeforeEach(func() {
		hostKey = hostKeyPem
		privateUserKey = privateUserKeyPem
		publicUserKey = publicUserKeyPem

		allowUnauthenticatedClients = false
		address = fmt.Sprintf("127.0.0.1:%d", sshdPort)
	})

	Describe("argument validation", func() {
		JustBeforeEach(func() {
			runner = startSSHDaemon()
			process = ifrit.Invoke(runner)
		})

		AfterEach(func() {
			ginkgomon.Kill(process, exitDuration)
		})

		Context("when a host key is not specified", func() {
			BeforeEach(func() {
				hostKey = []byte{}
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say("host-key-required"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when an ill-formed host key is provided", func() {
			BeforeEach(func() {
				hostKey = []byte("host-key")
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say("failed-to-parse-host-key"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when an ill-formed public user key is provided", func() {
			BeforeEach(func() {
				publicUserKey = []byte("user-key")
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say("invalid-public-user-key"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("the user public key is not provided", func() {
			BeforeEach(func() {
				publicUserKey = []byte{}
			})

			Context("and allowUnauthenticatedClients is not true", func() {
				BeforeEach(func() {
					allowUnauthenticatedClients = false
				})

				It("reports and dies", func() {
					Ω(runner).Should(gbytes.Say("public-user-key-required"))
					Ω(runner).ShouldNot(gexec.Exit(0))
				})
			})

			Context("and allowUnauthenticatedClients is true", func() {
				BeforeEach(func() {
					allowUnauthenticatedClients = true
				})

				It("starts normally", func() {
					Ω(process).ShouldNot(BeNil())
				})
			})

			Context("and a host key is not specified", func() {
				BeforeEach(func() {
					hostKey = []byte{}
				})

				It("reports both errors", func() {
					Ω(runner).Should(gbytes.Say("host-key-required"))
					Ω(runner).Should(gbytes.Say("public-user-key-required"))
				})

				It("fails to start", func() {
					Ω(runner).ShouldNot(gexec.Exit(0))
				})
			})
		})
	})

	Describe("execution", func() {
		var (
			client       *ssh.Client
			dialErr      error
			clientConfig *ssh.ClientConfig
		)

		JustBeforeEach(func() {
			runner = startSSHDaemon()
			process = ginkgomon.Invoke(runner)
			Ω(process).ShouldNot(BeNil())

			client, dialErr = ssh.Dial("tcp", address, clientConfig)
		})

		AfterEach(func() {
			ginkgomon.Interrupt(process, exitDuration)
		})

		Context("when unauthenticated clients are not allowed", func() {
			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{}
			})

			It("starts the daemon", func() {
				Ω(process).ShouldNot(BeNil())
			})

			It("rejects the client handshake", func() {
				Ω(dialErr).Should(MatchError(ContainSubstring("ssh: handshake failed")))
			})

			Context("and client has a valid private key", func() {
				BeforeEach(func() {
					key, err := ssh.ParsePrivateKey(privateUserKey)
					Ω(err).ShouldNot(HaveOccurred())

					clientConfig = &ssh.ClientConfig{
						User: os.Getenv("USER"),
						Auth: []ssh.AuthMethod{
							ssh.PublicKeys(key),
						},
					}
				})

				It("can complete a handshake with the daemon", func() {
					Ω(dialErr).ShouldNot(HaveOccurred())
					Ω(client).ShouldNot(BeNil())
				})
			})
		})

		Context("when the daemon allows unauthenticated clients", func() {
			BeforeEach(func() {
				allowUnauthenticatedClients = true
				clientConfig = &ssh.ClientConfig{}
			})

			It("starts the daemon", func() {
				Ω(process).ShouldNot(BeNil())
			})

			It("allows a client without credentials to complete a handshake", func() {
				Ω(dialErr).ShouldNot(HaveOccurred())
				Ω(client).ShouldNot(BeNil())
			})

			It("allows a client without credentials to execute commands", func() {
				session, err := client.NewSession()
				Ω(err).ShouldNot(HaveOccurred())

				result, err := session.Output("/bin/echo -n 'Hello there!'")
				Ω(err).ShouldNot(HaveOccurred())

				Ω(string(result)).Should(Equal("Hello there!"))
			})
		})
	})
})
