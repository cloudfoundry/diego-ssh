package main_test

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd/testrunner"
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
		runner  ifrit.Runner
		process ifrit.Process

		address       string
		hostKey       string
		privateKey    string
		authorizedKey string

		allowUnauthenticatedClients bool
	)

	BeforeEach(func() {
		hostKey = hostKeyPem
		privateKey = privateKeyPem
		authorizedKey = publicAuthorizedKey

		allowUnauthenticatedClients = false
		address = fmt.Sprintf("127.0.0.1:%d", sshdPort)
	})

	JustBeforeEach(func() {
		args := testrunner.Args{
			Address:       address,
			HostKey:       string(hostKey),
			AuthorizedKey: string(authorizedKey),

			AllowUnauthenticatedClients: allowUnauthenticatedClients,
		}

		runner = testrunner.New(sshdPath, args)
		process = ifrit.Invoke(runner)
	})

	AfterEach(func() {
		ginkgomon.Kill(process, 3*time.Second)
	})

	Describe("argument validation", func() {
		Context("when an ill-formed host key is provided", func() {
			BeforeEach(func() {
				hostKey = "host-key"
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say("failed-to-parse-host-key"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when an ill-formed authorized key is provided", func() {
			BeforeEach(func() {
				authorizedKey = "authorized-key"
			})

			It("reports and dies", func() {
				Ω(runner).Should(gbytes.Say(`configure-failed.*ssh: no key found`))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("the authorized key is not provided", func() {
			BeforeEach(func() {
				authorizedKey = ""
			})

			Context("and allowUnauthenticatedClients is not true", func() {
				BeforeEach(func() {
					allowUnauthenticatedClients = false
				})

				It("reports and dies", func() {
					Ω(runner).Should(gbytes.Say("authorized-key-required"))
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
		})
	})

	Describe("execution", func() {
		var (
			client       *ssh.Client
			dialErr      error
			clientConfig *ssh.ClientConfig
		)

		JustBeforeEach(func() {
			Ω(process).ShouldNot(BeNil())
			client, dialErr = ssh.Dial("tcp", address, clientConfig)
		})

		AfterEach(func() {
			if client != nil {
				client.Close()
			}
		})

		Context("when a host key is not specified", func() {
			BeforeEach(func() {
				hostKey = ""
				allowUnauthenticatedClients = true
				clientConfig = &ssh.ClientConfig{}
			})

			It("generates one internally", func() {
				Ω(process).ShouldNot(BeNil())

				Ω(client).ShouldNot(BeNil())
				Ω(dialErr).ShouldNot(HaveOccurred())
			})
		})

		Context("when a host key is specified", func() {
			var handshakeHostKey ssh.PublicKey

			BeforeEach(func() {
				allowUnauthenticatedClients = true
				clientConfig = &ssh.ClientConfig{
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						handshakeHostKey = key
						return nil
					},
				}
			})

			It("uses the host key provided on the command line", func() {
				sshHostKey, err := ssh.ParsePrivateKey([]byte(hostKeyPem))
				Ω(err).ShouldNot(HaveOccurred())

				sshPublicHostKey := sshHostKey.PublicKey()
				Ω(sshPublicHostKey.Marshal()).Should(Equal(handshakeHostKey.Marshal()))
			})
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
					key, err := ssh.ParsePrivateKey([]byte(privateKey))
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
