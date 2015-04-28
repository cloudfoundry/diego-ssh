package main_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cmd/sshd/testrunner"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
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
				Expect(runner).To(gbytes.Say("failed-to-parse-host-key"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when an ill-formed authorized key is provided", func() {
			BeforeEach(func() {
				authorizedKey = "authorized-key"
			})

			It("reports and dies", func() {
				Expect(runner).To(gbytes.Say(`configure-failed.*ssh: no key found`))
				Expect(runner).NotTo(gexec.Exit(0))
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
					Expect(runner).To(gbytes.Say("authorized-key-required"))
					Expect(runner).NotTo(gexec.Exit(0))
				})
			})

			Context("and allowUnauthenticatedClients is true", func() {
				BeforeEach(func() {
					allowUnauthenticatedClients = true
				})

				It("starts normally", func() {
					Expect(process).NotTo(BeNil())
				})
			})
		})
	})

	Describe("daemon execution", func() {
		var (
			client       *ssh.Client
			dialErr      error
			clientConfig *ssh.ClientConfig
		)

		JustBeforeEach(func() {
			Expect(process).NotTo(BeNil())
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
				Expect(process).NotTo(BeNil())

				Expect(client).NotTo(BeNil())
				Expect(dialErr).NotTo(HaveOccurred())
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
				Expect(err).NotTo(HaveOccurred())

				sshPublicHostKey := sshHostKey.PublicKey()
				Expect(sshPublicHostKey.Marshal()).To(Equal(handshakeHostKey.Marshal()))
			})
		})

		Context("when unauthenticated clients are not allowed", func() {
			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{}
			})

			It("starts the daemon", func() {
				Expect(process).NotTo(BeNil())
			})

			It("rejects the client handshake", func() {
				Expect(dialErr).To(MatchError(ContainSubstring("ssh: handshake failed")))
			})

			Context("and client has a valid private key", func() {
				BeforeEach(func() {
					key, err := ssh.ParsePrivateKey([]byte(privateKey))
					Expect(err).NotTo(HaveOccurred())

					clientConfig = &ssh.ClientConfig{
						User: os.Getenv("USER"),
						Auth: []ssh.AuthMethod{
							ssh.PublicKeys(key),
						},
					}
				})

				It("can complete a handshake with the daemon", func() {
					Expect(dialErr).NotTo(HaveOccurred())
					Expect(client).NotTo(BeNil())
				})
			})
		})

		Context("when the daemon allows unauthenticated clients", func() {
			BeforeEach(func() {
				allowUnauthenticatedClients = true
				clientConfig = &ssh.ClientConfig{}
			})

			It("starts the daemon", func() {
				Expect(process).NotTo(BeNil())
			})

			It("allows a client without credentials to complete a handshake", func() {
				Expect(dialErr).NotTo(HaveOccurred())
				Expect(client).NotTo(BeNil())
			})

		})
	})

	Describe("SSH features", func() {
		var clientConfig *ssh.ClientConfig
		var client *ssh.Client

		BeforeEach(func() {
			allowUnauthenticatedClients = true
			clientConfig = &ssh.ClientConfig{}
		})

		JustBeforeEach(func() {
			Expect(process).NotTo(BeNil())

			var dialErr error
			client, dialErr = ssh.Dial("tcp", address, clientConfig)
			Expect(dialErr).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			client.Close()
		})

		Context("when a client requests the execution of a command", func() {
			It("runs the command", func() {
				session, err := client.NewSession()
				Expect(err).NotTo(HaveOccurred())

				result, err := session.Output("/bin/echo -n 'Hello there!'")
				Expect(err).NotTo(HaveOccurred())

				Expect(string(result)).To(Equal("Hello there!"))
			})
		})

		Context("when a client requests a shell", func() {
			It("creates a shell environment", func() {
				session, err := client.NewSession()
				Expect(err).NotTo(HaveOccurred())

				stdout := &bytes.Buffer{}

				session.Stdin = strings.NewReader("/bin/echo -n $ENV_VAR")
				session.Stdout = stdout

				session.Setenv("ENV_VAR", "env_var_value")
				err = session.Shell()
				Expect(err).NotTo(HaveOccurred())

				err = session.Wait()
				Expect(err).NotTo(HaveOccurred())

				Expect(stdout.String()).To(ContainSubstring("env_var_value"))
			})
		})

		Context("when a client requests a local port forward", func() {
			var server *ghttp.Server
			BeforeEach(func() {
				server = ghttp.NewServer()
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/"),
						ghttp.RespondWith(http.StatusOK, "hi from jim\n"),
					),
				)
			})

			It("forwards the local port to the target from the server side", func() {
				lconn, err := client.Dial("tcp", server.Addr())
				Expect(err).NotTo(HaveOccurred())

				transport := &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return lconn, nil
					},
				}
				client := &http.Client{Transport: transport}

				resp, err := client.Get("http://127.0.0.1/")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				reader := bufio.NewReader(resp.Body)
				line, err := reader.ReadString('\n')
				Expect(err).NotTo(HaveOccurred())
				Expect(line).To(ContainSubstring("hi from jim"))
			})
		})
	})
})
