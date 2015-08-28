// +build !windows

package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/cmd/ssh-proxy/testrunner"
	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
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

		address            string
		hostKey            string
		hostKeyFingerprint string
		diegoAPIURL        string
		ccAPIURL           string
		enableCFAuth       bool
		enableDiegoAuth    bool
	)

	BeforeEach(func() {
		fakeReceptor = ghttp.NewServer()

		hostKey = hostKeyPem

		privateKey, err := ssh.ParsePrivateKey([]byte(hostKey))
		Expect(err).NotTo(HaveOccurred())
		hostKeyFingerprint = helpers.MD5Fingerprint(privateKey.PublicKey())

		address = fmt.Sprintf("127.0.0.1:%d", sshProxyPort)
		diegoAPIURL = fakeReceptor.URL()

		ccAPIURL = ""
		enableCFAuth = true
		enableDiegoAuth = true
	})

	JustBeforeEach(func() {
		args := testrunner.Args{
			Address:         address,
			HostKey:         hostKey,
			DiegoAPIURL:     diegoAPIURL,
			CCAPIURL:        ccAPIURL,
			EnableCFAuth:    enableCFAuth,
			EnableDiegoAuth: enableDiegoAuth,
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
				Expect(runner).To(gbytes.Say("hostKey is required"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when an ill-formed host key is provided", func() {
			BeforeEach(func() {
				hostKey = "host-key"
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("failed-to-parse-host-key"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when the diego URL is missing", func() {
			BeforeEach(func() {
				diegoAPIURL = ""
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("diegoAPIURL is required"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when the diego URL cannot be parsed", func() {
			BeforeEach(func() {
				diegoAPIURL = ":://goober-swallow#yuck"
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("failed-to-parse-diego-api-url"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when the cc URL cannot be parsed", func() {
			BeforeEach(func() {
				ccAPIURL = ":://goober-swallow#yuck"
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("failed-to-parse-cc-api-url"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})
	})

	Describe("execution", func() {
		var (
			clientConfig *ssh.ClientConfig
			processGuid  string
		)

		BeforeEach(func() {
			processGuid = "process-guid"
			clientConfig = &ssh.ClientConfig{
				User: "user",
				Auth: []ssh.AuthMethod{ssh.Password("")},
			}
		})

		JustBeforeEach(func() {
			sshRoute := routes.SSHRoute{
				ContainerPort:   9999,
				PrivateKey:      privateKeyPem,
				HostFingerprint: hostKeyFingerprint,
			}

			sshRoutePayload, err := json.Marshal(sshRoute)
			Expect(err).NotTo(HaveOccurred())

			diegoSSHRouteMessage := json.RawMessage(sshRoutePayload)

			desiredLRP := receptor.DesiredLRPResponse{
				ProcessGuid: processGuid,
				Instances:   1,
				Routes: receptor.RoutingInfo{
					routes.DIEGO_SSH: &diegoSSHRouteMessage,
				},
			}

			actualLRP := receptor.ActualLRPResponse{
				ProcessGuid:  processGuid,
				Index:        0,
				InstanceGuid: "some-instance-guid",
				Address:      "127.0.0.1",
				Ports: []receptor.PortMapping{
					{ContainerPort: 9999, HostPort: uint16(sshdPort)},
				},
			}

			fakeReceptor.RouteToHandler("GET", "/v1/desired_lrps/"+processGuid,
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/v1/desired_lrps/"+processGuid),
					ghttp.RespondWithJSONEncoded(http.StatusOK, desiredLRP),
				),
			)

			fakeReceptor.RouteToHandler("GET", "/v1/actual_lrps/"+processGuid+"/index/0",
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/v1/actual_lrps/"+processGuid+"/index/0"),
					ghttp.RespondWithJSONEncoded(http.StatusOK, actualLRP),
				),
			)

			Expect(process).NotTo(BeNil())
		})

		Context("when the client attempts to verify the host key", func() {
			var handshakeHostKey ssh.PublicKey

			BeforeEach(func() {
				clientConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					handshakeHostKey = key
					return errors.New("fail")
				}
			})

			It("receives the correct host key", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).To(HaveOccurred())

				proxyHostKey, err := ssh.ParsePrivateKey([]byte(hostKeyPem))
				Expect(err).NotTo(HaveOccurred())

				proxyPublicHostKey := proxyHostKey.PublicKey()
				Expect(proxyPublicHostKey.Marshal()).To(Equal(handshakeHostKey.Marshal()))
			})
		})

		Context("when the client uses the cf realm", func() {
			var fakeCC *ghttp.Server

			BeforeEach(func() {
				processGuid = "app-guid-app-version"

				clientConfig = &ssh.ClientConfig{
					User: "cf:app-guid/0",
					Auth: []ssh.AuthMethod{ssh.Password("bearer token")},
				}

				fakeCC = ghttp.NewServer()
				ccAPIURL = fakeCC.URL()

				ccAppResponse := authenticators.AppSSHResponse{
					ProcessGuid: "app-guid-app-version",
				}

				fakeCC.RouteToHandler("GET", "/internal/apps/app-guid/ssh_access",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
						ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
						ghttp.RespondWithJSONEncoded(http.StatusOK, ccAppResponse),
					),
				)
			})

			Context("when the client authenticates with the right data", func() {
				It("acquires the lrp info from the receptor", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					client.Close()

					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(2))
				})

				It("connects to the target daemon", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					session, err := client.NewSession()
					Expect(err).NotTo(HaveOccurred())

					output, err := session.Output("echo -n hello")
					Expect(err).NotTo(HaveOccurred())

					Expect(string(output)).To(Equal("hello"))
				})
			})

			Context("when authentication fails", func() {
				BeforeEach(func() {
					clientConfig.Auth = []ssh.AuthMethod{ssh.Password("bad password")}
					fakeCC.RouteToHandler("GET", "/internal/apps/app-guid/ssh_access",
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
							ghttp.RespondWithJSONEncoded(http.StatusUnauthorized, ""),
						),
					)
				})

				It("logs the authentication failure", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
					Expect(runner).To(gbytes.Say("authentication-failed.*cf:app-guid/0"))
				})
			})

			Context("when the app-guid does not exist in cc", func() {
				BeforeEach(func() {
					clientConfig.User = "cf:bad-app-guid/0"

					fakeCC.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/internal/apps/bad-app-guid/ssh_access"),
							ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
							ghttp.RespondWithJSONEncoded(http.StatusNotFound, nil),
						),
					)
				})

				It("attempts to acquire the app info from cc", func() {
					ssh.Dial("tcp", address, clientConfig)
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
				})
			})

			Context("when the instance index does not exist", func() {
				BeforeEach(func() {
					clientConfig.User = "cf:bad-app-guid/0"

					ccAppResponse := authenticators.AppSSHResponse{
						ProcessGuid: "bad-app-guid-app-version",
					}

					fakeCC.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/internal/apps/bad-app-guid/ssh_access"),
							ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
							ghttp.RespondWithJSONEncoded(http.StatusOK, ccAppResponse),
						),
					)

					fakeReceptor.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("GET", "/v1/actual_lrps/bad-app-guid-app-version/index/0"),
							ghttp.RespondWithJSONEncoded(http.StatusNotFound, nil),
						),
					)
				})

				It("attempts to acquire the app info from receptor", func() {
					ssh.Dial("tcp", address, clientConfig)
					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(1))
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
				})
			})

			Context("when the ccAPIURL is not configured", func() {
				BeforeEach(func() {
					ccAPIURL = ""
				})

				It("fails authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
				})

				It("does not attempt to grab the app info from cc", func() {
					ssh.Dial("tcp", address, clientConfig)
					Consistently(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("and the enableCFAuth flag is set to false", func() {
				BeforeEach(func() {
					enableCFAuth = false
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(0))
				})
			})
		})

		Context("when the client uses the diego realm", func() {
			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{
					User: "diego:process-guid/0",
					Auth: []ssh.AuthMethod{ssh.Password("")},
				}
			})

			Context("when the client authenticates with the right data", func() {
				It("acquires the lrp info from the receptor", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					client.Close()

					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(2))
				})

				It("connects to the target daemon", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					session, err := client.NewSession()
					Expect(err).NotTo(HaveOccurred())

					output, err := session.Output("echo -n hello")
					Expect(err).NotTo(HaveOccurred())

					Expect(string(output)).To(Equal("hello"))
				})
			})

			Context("when a client connects with a bad user", func() {
				BeforeEach(func() {
					clientConfig.User = "cf-user"
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
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
					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(1))
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
				})
			})

			Context("and the enableDiegoAuth flag is set to false", func() {
				BeforeEach(func() {
					enableDiegoAuth = false
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
					Expect(fakeReceptor.ReceivedRequests()).To(HaveLen(0))
				})
			})
		})
	})
})
