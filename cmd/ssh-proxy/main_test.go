// +build !windows

package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/cloudfoundry-incubator/bbs/models"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/cmd/ssh-proxy/testrunner"
	"github.com/cloudfoundry-incubator/diego-ssh/helpers"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/gogo/protobuf/proto"
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
		fakeBBS      *ghttp.Server
		runner       ifrit.Runner
		process      ifrit.Process
		exitDuration = 3 * time.Second

		diegoCredentials string

		address            string
		hostKey            string
		hostKeyFingerprint string
		bbsAddress         string
		ccAPIURL           string
		enableCFAuth       bool
		enableDiegoAuth    bool
		skipCertVerify     bool
	)

	BeforeEach(func() {
		fakeBBS = ghttp.NewServer()

		hostKey = hostKeyPem

		privateKey, err := ssh.ParsePrivateKey([]byte(hostKey))
		Expect(err).NotTo(HaveOccurred())
		hostKeyFingerprint = helpers.MD5Fingerprint(privateKey.PublicKey())

		address = fmt.Sprintf("127.0.0.1:%d", sshProxyPort)
		bbsAddress = fakeBBS.URL()

		diegoCredentials = "some-creds"
		ccAPIURL = ""
		enableCFAuth = true
		enableDiegoAuth = true
		skipCertVerify = true
	})

	JustBeforeEach(func() {
		args := testrunner.Args{
			DiegoCredentials: diegoCredentials,
			Address:          address,
			HostKey:          hostKey,
			BBSAddress:       bbsAddress,
			CCAPIURL:         ccAPIURL,
			SkipCertVerify:   skipCertVerify,
			EnableCFAuth:     enableCFAuth,
			EnableDiegoAuth:  enableDiegoAuth,
		}

		runner = testrunner.New(sshProxyPath, args)
		process = ifrit.Invoke(runner)
	})

	AfterEach(func() {
		fakeBBS.Close()
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

		Context("when the BBS address is missing", func() {
			BeforeEach(func() {
				bbsAddress = ""
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("bbsAddress is required"))
				Expect(runner).NotTo(gexec.Exit(0))
			})
		})

		Context("when the BBS address cannot be parsed", func() {
			BeforeEach(func() {
				bbsAddress = ":://goober-swallow#yuck"
			})

			It("reports the problem and terminates", func() {
				Expect(runner).To(gbytes.Say("failed-to-parse-bbs-address"))
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

			desiredLRPRequest  *models.DesiredLRPByProcessGuidRequest
			desiredLRPResponse *models.DesiredLRPResponse

			actualLRPRequest  *models.ActualLRPGroupByProcessGuidAndIndexRequest
			actualLRPResponse *models.ActualLRPGroupResponse
		)

		BeforeEach(func() {
			processGuid = "process-guid"
			clientConfig = &ssh.ClientConfig{
				User: "user",
				Auth: []ssh.AuthMethod{ssh.Password("")},
			}
		})

		VerifyProto := func(expectedProto proto.Message, protoType proto.Message) http.HandlerFunc {
			return ghttp.CombineHandlers(
				ghttp.VerifyContentType("application/x-protobuf"),
				func(w http.ResponseWriter, req *http.Request) {
					body, err := ioutil.ReadAll(req.Body)
					Expect(err).ToNot(HaveOccurred())
					req.Body.Close()
					err = proto.Unmarshal(body, protoType)
					Expect(err).ToNot(HaveOccurred())
					Expect(protoType).To(Equal(expectedProto), "ProtoBuf Mismatch")
				},
			)
		}

		RespondWithProto := func(message proto.Message) http.HandlerFunc {
			data, err := proto.Marshal(message)
			Expect(err).ToNot(HaveOccurred())

			var headers = make(http.Header)
			headers["Content-Type"] = []string{"application/x-protobuf"}
			return ghttp.RespondWith(200, string(data), headers)
		}

		JustBeforeEach(func() {
			sshRoute := routes.SSHRoute{
				ContainerPort:   9999,
				PrivateKey:      privateKeyPem,
				HostFingerprint: hostKeyFingerprint,
			}

			sshRoutePayload, err := json.Marshal(sshRoute)
			Expect(err).NotTo(HaveOccurred())

			diegoSSHRouteMessage := json.RawMessage(sshRoutePayload)

			desiredLRP := &models.DesiredLRP{
				ProcessGuid: processGuid,
				Instances:   1,
				Routes: &models.Routes{
					routes.DIEGO_SSH: &diegoSSHRouteMessage,
				},
			}

			desiredLRPRequest = &models.DesiredLRPByProcessGuidRequest{ProcessGuid: processGuid}
			desiredLRPResponse = &models.DesiredLRPResponse{
				Error:      nil,
				DesiredLrp: desiredLRP,
			}

			actualLRP := &models.ActualLRP{
				ActualLRPKey:         models.NewActualLRPKey(processGuid, 0, "some-domain"),
				ActualLRPInstanceKey: models.NewActualLRPInstanceKey("some-instance-guid", "some-cell-id"),
				ActualLRPNetInfo:     models.NewActualLRPNetInfo("127.0.0.1", models.NewPortMapping(uint32(sshdPort), 9999)),
			}

			actualLRPRequest = &models.ActualLRPGroupByProcessGuidAndIndexRequest{ProcessGuid: processGuid, Index: 0}
			actualLRPResponse = &models.ActualLRPGroupResponse{
				Error:          nil,
				ActualLrpGroup: &models.ActualLRPGroup{Instance: actualLRP},
			}

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

			JustBeforeEach(func() {
				fakeBBS.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
						VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
						RespondWithProto(desiredLRPResponse),
					),
				)

				fakeBBS.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
						VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
						RespondWithProto(actualLRPResponse),
					),
				)
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

				fakeCC = ghttp.NewTLSServer()
				fakeCC.RouteToHandler("GET", "/internal/apps/app-guid/ssh_access",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
						ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
						ghttp.RespondWithJSONEncoded(http.StatusOK, authenticators.AppSSHResponse{
							ProcessGuid: processGuid,
						}),
					),
				)

				ccAPIURL = fakeCC.URL()
			})

			AfterEach(func() {
				fakeCC.Close()
			})

			Context("when the client authenticates with the right data", func() {
				JustBeforeEach(func() {
					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
						),
					)

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
							VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
							RespondWithProto(desiredLRPResponse),
						),
					)
				})

				It("acquires the lrp info from the BBS", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					client.Close()

					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(2))
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

			Context("when skipCertVerify is false and the CC does not have a valid certificate", func() {
				BeforeEach(func() {
					skipCertVerify = false
				})

				It("fails the authentication", func() {
					_, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
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

				JustBeforeEach(func() {
					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
							VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
							RespondWithProto(desiredLRPResponse),
						),
					)

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
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

				JustBeforeEach(func() {
					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
							VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
							RespondWithProto(desiredLRPResponse),
						),
					)

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
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

					actualLRPRequest := &models.ActualLRPGroupByProcessGuidAndIndexRequest{
						ProcessGuid: "bad-app-guid-app-version",
						Index:       0,
					}
					actualLRPResponse := &models.ActualLRPGroupResponse{
						Error:          models.ErrResourceNotFound,
						ActualLrpGroup: nil,
					}

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
						),
					)
				})

				JustBeforeEach(func() {
					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
							VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
							RespondWithProto(desiredLRPResponse),
						),
					)

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
						),
					)
				})

				It("attempts to acquire the app info from BBS", func() {
					ssh.Dial("tcp", address, clientConfig)
					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(1))
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
					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
				})
			})
		})

		Context("when the client uses the diego realm", func() {
			BeforeEach(func() {
				clientConfig = &ssh.ClientConfig{
					User: "diego:process-guid/0",
					Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
				}
			})

			Context("when the client authenticates with the right data", func() {
				JustBeforeEach(func() {
					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
						),
					)

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid"),
							VerifyProto(desiredLRPRequest, &models.DesiredLRPByProcessGuidRequest{}),
							RespondWithProto(desiredLRPResponse),
						),
					)
				})

				It("acquires the lrp info from the BBS", func() {
					client, err := ssh.Dial("tcp", address, clientConfig)
					Expect(err).NotTo(HaveOccurred())

					client.Close()

					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(2))
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

					actualLRPRequest := &models.ActualLRPGroupByProcessGuidAndIndexRequest{
						ProcessGuid: "bad-process-guid",
						Index:       0,
					}
					actualLRPResponse := &models.ActualLRPGroupResponse{
						Error:          models.ErrResourceNotFound,
						ActualLrpGroup: nil,
					}

					fakeBBS.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
							VerifyProto(actualLRPRequest, &models.ActualLRPGroupByProcessGuidAndIndexRequest{}),
							RespondWithProto(actualLRPResponse),
						),
					)
				})

				It("attempts to acquire the lrp info from the BBS", func() {
					ssh.Dial("tcp", address, clientConfig)
					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(1))
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
					Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
				})
			})
		})
	})
})
