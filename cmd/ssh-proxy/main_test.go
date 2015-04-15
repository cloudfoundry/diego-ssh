package main_test

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/cmd/ssh-proxy/testrunner"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("SSH proxy", func() {
	var (
		fakeReceptor *ghttp.Server
		runner       ifrit.Runner
		process      ifrit.Process
		exitDuration = 3 * time.Second

		address     string
		hostKey     string
		privateKey  string
		diegoAPIURL string
	)

	BeforeEach(func() {
		fakeReceptor = ghttp.NewServer()

		hostKey = hostKeyPem
		address = fmt.Sprintf("127.0.0.1:%d", sshProxyPort)
		privateKey = privateUserKeyPem
		diegoAPIURL = fakeReceptor.URL()
	})

	JustBeforeEach(func() {
		args := testrunner.Args{
			Address:     address,
			HostKey:     hostKey,
			PrivateKey:  privateKey,
			DiegoAPIURL: diegoAPIURL,
		}

		runner = testrunner.New(sshProxyPath, args)
		process = ifrit.Invoke(runner)
	})

	AfterEach(func() {
		ginkgomon.Kill(process, exitDuration)
	})

	Describe("argument validation", func() {
		Context("when the host key is not provided", func() {
			BeforeEach(func() {
				hostKey = ""
			})

			It("reports the problem and terminates", func() {
				Ω(runner).Should(gbytes.Say("hostKey is required"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when an ill-formed host key is provided", func() {
			BeforeEach(func() {
				hostKey = "host-key"
			})

			It("reports the problem and terminates", func() {
				Ω(runner).Should(gbytes.Say("failed-to-parse-host-key"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when the diego URL is missing", func() {
			BeforeEach(func() {
				diegoAPIURL = ""
			})

			It("reports the problem and terminates", func() {
				Ω(runner).Should(gbytes.Say("diegoAPIURL is required"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})

		Context("when the diego URL cannot be parsed", func() {
			BeforeEach(func() {
				diegoAPIURL = ":://goober-swallow#yuck"
			})

			It("reports the problem and terminates", func() {
				Ω(runner).Should(gbytes.Say("failed-to-parse-diego-api-url"))
				Ω(runner).ShouldNot(gexec.Exit(0))
			})
		})
	})

	Describe("execution", func() {
		var clientConfig *ssh.ClientConfig

		BeforeEach(func() {
			clientConfig = &ssh.ClientConfig{
				User: "diego:process-guid/0",
				Auth: []ssh.AuthMethod{ssh.Password("")},
			}
		})

		JustBeforeEach(func() {
			Ω(process).ShouldNot(BeNil())
		})

		Context("when the client authenticates with the right data", func() {
			BeforeEach(func() {
				actualLRP := receptor.ActualLRPResponse{
					ProcessGuid:  "process-guid",
					Index:        0,
					InstanceGuid: "some-instance-guid",
					Address:      "127.0.0.1",
					Ports: []receptor.PortMapping{
						{ContainerPort: 2222, HostPort: uint16(sshdPort)},
					},
				}

				fakeReceptor.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/v1/actual_lrps/process-guid/index/0"),
						ghttp.RespondWithJSONEncoded(http.StatusOK, actualLRP),
					),
				)
			})

			It("acquires the lrp info from the receptor", func() {
				client, err := ssh.Dial("tcp", address, clientConfig)
				Ω(err).ShouldNot(HaveOccurred())

				client.Close()

				Ω(fakeReceptor.ReceivedRequests()).Should(HaveLen(1))
			})
		})

		Context("when a client connects with a bad user", func() {
			BeforeEach(func() {
				clientConfig.User = "cf-user"
			})

			It("fails the authentication", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Ω(err).Should(MatchError(ContainSubstring("ssh: handshake failed")))
			})
		})

		Context("when a client uses a bad process guid", func() {
			BeforeEach(func() {
				clientConfig.User = "diego:bad-process-guid/0"

				fakeReceptor.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/v1/actual_lrps/bad-process-guid/index/0"),
						ghttp.RespondWithJSONEncoded(http.StatusNotFound, nil),
					),
				)
			})

			It("attempts to acquire the lrp info from the receptor", func() {
				ssh.Dial("tcp", address, clientConfig)
				Ω(fakeReceptor.ReceivedRequests()).Should(HaveLen(1))
			})

			It("fails the authentication", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Ω(err).Should(MatchError(ContainSubstring("ssh: handshake failed")))
			})
		})
	})
})
