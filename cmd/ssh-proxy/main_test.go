package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/diego-ssh/authenticators"
	"code.cloudfoundry.org/diego-ssh/cmd/ssh-proxy/testrunner"
	"code.cloudfoundry.org/diego-ssh/helpers"
	"code.cloudfoundry.org/diego-ssh/routes"
	"github.com/gogo/protobuf/proto"
	"github.com/hashicorp/consul/api"
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
		fakeBBS *ghttp.Server
		fakeUAA *ghttp.Server
		fakeCC  *ghttp.Server
		runner  ifrit.Runner
		process ifrit.Process

		address                     string
		healthCheckAddress          string
		bbsAddress                  string
		ccAPIURL                    string
		diegoCredentials            string
		enableCFAuth                bool
		enableDiegoAuth             bool
		hostKey                     string
		hostKeyFingerprint          string
		skipCertVerify              bool
		uaaTokenURL                 string
		uaaPassword                 string
		uaaUsername                 string
		allowedCiphers              string
		allowedMACs                 string
		allowedKeyExchanges         string
		expectedGetActualLRPRequest *models.ActualLRPGroupByProcessGuidAndIndexRequest
		actualLRPGroupResponse      *models.ActualLRPGroupResponse
		getDesiredLRPRequest        *models.DesiredLRPByProcessGuidRequest
		desiredLRPResponse          *models.DesiredLRPResponse

		processGuid  string
		clientConfig *ssh.ClientConfig
	)

	BeforeEach(func() {
		fakeBBS = ghttp.NewServer()
		fakeUAA = ghttp.NewTLSServer()
		fakeCC = ghttp.NewTLSServer()

		privateKey, err := ssh.ParsePrivateKey([]byte(hostKeyPem))
		Expect(err).NotTo(HaveOccurred())
		hostKeyFingerprint = helpers.MD5Fingerprint(privateKey.PublicKey())

		address = fmt.Sprintf("127.0.0.1:%d", sshProxyPort)
		healthCheckAddress = fmt.Sprintf("127.0.0.1:%d", healthCheckProxyPort)
		bbsAddress = fakeBBS.URL()
		ccAPIURL = fakeCC.URL()
		diegoCredentials = "some-creds"
		enableCFAuth = true
		enableDiegoAuth = true
		hostKey = hostKeyPem
		skipCertVerify = true
		processGuid = "app-guid-app-version"

		u, err := url.Parse(fakeUAA.URL())
		Expect(err).NotTo(HaveOccurred())

		u.Path = "/oauth/token"
		uaaTokenURL = u.String()
		uaaPassword = "password1"
		uaaUsername = "amandaplease"

		allowedCiphers = ""
		allowedMACs = ""
		allowedKeyExchanges = ""

		expectedGetActualLRPRequest = &models.ActualLRPGroupByProcessGuidAndIndexRequest{
			ProcessGuid: processGuid,
			Index:       99,
		}

		actualLRPGroupResponse = &models.ActualLRPGroupResponse{
			Error: nil,
			ActualLrpGroup: &models.ActualLRPGroup{
				Instance: &models.ActualLRP{
					ActualLRPKey:         models.NewActualLRPKey(processGuid, 99, "some-domain"),
					ActualLRPInstanceKey: models.NewActualLRPInstanceKey("some-instance-guid", "some-cell-id"),
					ActualLRPNetInfo:     models.NewActualLRPNetInfo("127.0.0.1", models.NewPortMapping(uint32(sshdPort), 9999)),
				},
			},
		}

		getDesiredLRPRequest = &models.DesiredLRPByProcessGuidRequest{
			ProcessGuid: processGuid,
		}

		sshRoute, err := json.Marshal(routes.SSHRoute{
			ContainerPort:   9999,
			PrivateKey:      privateKeyPem,
			HostFingerprint: hostKeyFingerprint,
		})
		Expect(err).NotTo(HaveOccurred())

		sshRouteMessage := json.RawMessage(sshRoute)
		desiredLRPResponse = &models.DesiredLRPResponse{
			Error: nil,
			DesiredLrp: &models.DesiredLRP{
				ProcessGuid: processGuid,
				Instances:   100,
				Routes:      &models.Routes{routes.DIEGO_SSH: &sshRouteMessage},
			},
		}

		clientConfig = &ssh.ClientConfig{}
	})

	JustBeforeEach(func() {
		fakeBBS.RouteToHandler("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index", ghttp.CombineHandlers(
			ghttp.VerifyRequest("POST", "/v1/actual_lrp_groups/get_by_process_guid_and_index"),
			VerifyProto(expectedGetActualLRPRequest),
			RespondWithProto(actualLRPGroupResponse),
		))
		fakeBBS.RouteToHandler("POST", "/v1/desired_lrps/get_by_process_guid.r2", ghttp.CombineHandlers(
			ghttp.VerifyRequest("POST", "/v1/desired_lrps/get_by_process_guid.r2"),
			VerifyProto(getDesiredLRPRequest),
			RespondWithProto(desiredLRPResponse),
		))

		args := testrunner.Args{
			Address:             address,
			HealthCheckAddress:  healthCheckAddress,
			BBSAddress:          bbsAddress,
			CCAPIURL:            ccAPIURL,
			DiegoCredentials:    diegoCredentials,
			EnableCFAuth:        enableCFAuth,
			EnableDiegoAuth:     enableDiegoAuth,
			HostKey:             hostKey,
			SkipCertVerify:      skipCertVerify,
			UAATokenURL:         uaaTokenURL,
			UAAPassword:         uaaPassword,
			UAAUsername:         uaaUsername,
			ConsulCluster:       consulRunner.URL(),
			AllowedCiphers:      allowedCiphers,
			AllowedMACs:         allowedMACs,
			AllowedKeyExchanges: allowedKeyExchanges,
		}

		runner = testrunner.New(sshProxyPath, args)
		process = ifrit.Invoke(runner)
	})

	AfterEach(func() {
		ginkgomon.Kill(process, 3*time.Second)

		fakeBBS.Close()
		fakeUAA.Close()
		fakeCC.Close()
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

		Context("when CF authentication is enabled", func() {
			BeforeEach(func() {
				enableCFAuth = true
			})

			Context("when the cc URL is missing", func() {
				BeforeEach(func() {
					ccAPIURL = ""
				})

				It("reports the problem and terminates", func() {
					Expect(runner).To(gbytes.Say("ccAPIURL is required for Cloud Foundry authentication"))
					Expect(runner).NotTo(gexec.Exit(0))
				})
			})

			Context("when the cc URL cannot be parsed", func() {
				BeforeEach(func() {
					ccAPIURL = ":://goober-swallow#yuck"
				})

				It("reports the problem and terminates", func() {
					Expect(runner).To(gbytes.Say("configure-failed"))
					Expect(runner).To(gexec.Exit(1))
				})
			})

			Context("when the uaa URL is missing", func() {
				BeforeEach(func() {
					uaaTokenURL = ""
				})

				It("reports the problem and terminates", func() {
					Expect(runner).To(gbytes.Say("uaaTokenURL is required for Cloud Foundry authentication"))
					Expect(runner).To(gexec.Exit(1))
				})
			})

			Context("when the UAA password is missing", func() {
				BeforeEach(func() {
					uaaPassword = ""
				})

				It("exits with an error", func() {
					Expect(runner).To(gbytes.Say("UAA password is required for Cloud Foundry authentication"))
					Expect(runner).To(gexec.Exit(1))
				})
			})

			Context("when the UAA username is missing", func() {
				BeforeEach(func() {
					uaaUsername = ""
				})

				It("exits with an error", func() {
					Expect(runner).To(gbytes.Say("UAA username is required for Cloud Foundry authentication"))
					Expect(runner).To(gexec.Exit(1))
				})
			})

			Context("when the UAA URL cannot be parsed", func() {
				BeforeEach(func() {
					uaaTokenURL = ":://spitting#nickles"
				})

				It("reports the problem and terminates", func() {
					Expect(runner).To(gbytes.Say("configure-failed"))
					Expect(runner).To(gexec.Exit(1))
				})
			})
		})
	})

	Describe("Initialization", func() {
		It("registers itself with consul", func() {
			services, err := consulRunner.NewClient().Agent().Services()
			Expect(err).NotTo(HaveOccurred())
			Expect(services).Should(HaveKeyWithValue("ssh-proxy",
				&api.AgentService{
					Service: "ssh-proxy",
					ID:      "ssh-proxy",
					Port:    sshProxyPort,
				}))
		})

		It("registers a TTL healthcheck", func() {
			checks, err := consulRunner.NewClient().Agent().Checks()
			Expect(err).NotTo(HaveOccurred())
			Expect(checks).Should(HaveKeyWithValue("service:ssh-proxy",
				&api.AgentCheck{
					Node:        "0",
					CheckID:     "service:ssh-proxy",
					Name:        "Service 'ssh-proxy' check",
					Status:      "passing",
					ServiceID:   "ssh-proxy",
					ServiceName: "ssh-proxy",
				}))
		})
	})
	It("presents the correct host key", func() {
		var handshakeHostKey ssh.PublicKey
		_, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
			User: "user",
			Auth: []ssh.AuthMethod{ssh.Password("")},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				handshakeHostKey = key
				return errors.New("Short-circuit the handshake")
			},
		})
		Expect(err).To(HaveOccurred())

		proxyHostKey, err := ssh.ParsePrivateKey([]byte(hostKeyPem))
		Expect(err).NotTo(HaveOccurred())
		Expect(proxyHostKey.PublicKey().Marshal()).To(Equal(handshakeHostKey.Marshal()))
	})

	Describe("attempting authentication without a realm", func() {
		BeforeEach(func() {
			clientConfig = &ssh.ClientConfig{
				User: processGuid + "/99",
				Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
			}
		})

		It("fails the authentication", func() {
			_, err := ssh.Dial("tcp", address, clientConfig)
			Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
			Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
		})
	})

	Describe("attempting authentication with an unknown realm", func() {
		BeforeEach(func() {
			clientConfig = &ssh.ClientConfig{
				User: "goo:" + processGuid + "/99",
				Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
			}
		})

		It("fails the authentication", func() {
			_, err := ssh.Dial("tcp", address, clientConfig)
			Expect(err).To(MatchError(ContainSubstring("ssh: handshake failed")))
			Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
		})
	})

	Describe("authenticating with the diego realm", func() {
		BeforeEach(func() {
			clientConfig = &ssh.ClientConfig{
				User: "diego:" + processGuid + "/99",
				Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
			}
		})

		It("acquires the desired and actual LRP info from the BBS", func() {
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

		Context("when the proxy provides an unsupported cipher algorithm", func() {
			BeforeEach(func() {
				allowedCiphers = "unsupported"
			})

			It("rejects the cipher algorithm", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).To(MatchError(ContainSubstring("ssh: no common algorithm for client to server cipher")))
				Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the proxy provides a supported cipher algorithm", func() {
			BeforeEach(func() {
				allowedCiphers = "aes128-ctr,aes256-ctr"
				clientConfig = &ssh.ClientConfig{
					User: "diego:" + processGuid + "/99",
					Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
				}
			})

			It("allows a client to complete a handshake", func() {
				client, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).NotTo(HaveOccurred())
				client.Close()
			})
		})

		Context("when the proxy provides an unsupported MAC algorithm", func() {
			BeforeEach(func() {
				allowedMACs = "unsupported"
			})

			It("rejects the MAC algorithm", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).To(MatchError(ContainSubstring("ssh: no common algorithm for client to server MAC")))
				Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the proxy provides a supported MAC algorithm", func() {
			BeforeEach(func() {
				allowedMACs = "hmac-sha2-256,hmac-sha1"
				clientConfig = &ssh.ClientConfig{
					User: "diego:" + processGuid + "/99",
					Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
				}
			})

			It("allows a client to complete a handshake", func() {
				client, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).NotTo(HaveOccurred())
				client.Close()
			})
		})

		Context("when the proxy provides an unsupported key exchange algorithm", func() {
			BeforeEach(func() {
				allowedKeyExchanges = "unsupported"
			})

			It("rejects the key exchange algorithm", func() {
				_, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).To(MatchError(ContainSubstring("ssh: no common algorithm for key exchange")))
				Expect(fakeBBS.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the proxy provides a supported key exchange algorithm", func() {
			BeforeEach(func() {
				allowedKeyExchanges = "curve25519-sha256@libssh.org,ecdh-sha2-nistp384,diffie-hellman-group14-sha1"
				clientConfig = &ssh.ClientConfig{
					User: "diego:" + processGuid + "/99",
					Auth: []ssh.AuthMethod{ssh.Password(diegoCredentials)},
				}
			})

			It("allows a client to complete a handshake", func() {
				client, err := ssh.Dial("tcp", address, clientConfig)
				Expect(err).NotTo(HaveOccurred())
				client.Close()
			})
		})

		Context("when a non-existent process guid is used", func() {
			BeforeEach(func() {
				clientConfig.User = "diego:bad-process-guid/999"
				expectedGetActualLRPRequest = &models.ActualLRPGroupByProcessGuidAndIndexRequest{
					ProcessGuid: "bad-process-guid",
					Index:       999,
				}
				actualLRPGroupResponse = &models.ActualLRPGroupResponse{
					Error: models.ErrResourceNotFound,
				}
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

		Context("when invalid credentials are presented", func() {
			BeforeEach(func() {
				clientConfig.Auth = []ssh.AuthMethod{
					ssh.Password("bogus-password"),
				}
			})

			It("fails diego authentication when the wrong credentials are used", func() {
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

	Describe("authenticating with the cf realm with a one time code", func() {
		BeforeEach(func() {
			clientConfig = &ssh.ClientConfig{
				User: "cf:60f0f26e-86b3-4487-8f19-9e94f848f3d2/99",
				Auth: []ssh.AuthMethod{ssh.Password("abc123")},
			}

			fakeUAA.RouteToHandler("POST", "/oauth/token", ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/oauth/token"),
				ghttp.VerifyBasicAuth("amandaplease", "password1"),
				ghttp.VerifyContentType("application/x-www-form-urlencoded"),
				ghttp.VerifyFormKV("grant_type", "authorization_code"),
				ghttp.VerifyFormKV("code", "abc123"),
				ghttp.RespondWithJSONEncoded(http.StatusOK, authenticators.UAAAuthTokenResponse{
					AccessToken: "proxy-token",
					TokenType:   "bearer",
				}),
			))

			fakeCC.RouteToHandler("GET", "/internal/apps/60f0f26e-86b3-4487-8f19-9e94f848f3d2/ssh_access/99", ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/internal/apps/60f0f26e-86b3-4487-8f19-9e94f848f3d2/ssh_access/99"),
				ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer proxy-token"}}),
				ghttp.RespondWithJSONEncoded(http.StatusOK, authenticators.AppSSHResponse{
					ProcessGuid: processGuid,
				}),
			))
		})

		It("provides the access code to the UAA and and gets an access token", func() {
			client, err := ssh.Dial("tcp", address, clientConfig)
			Expect(err).NotTo(HaveOccurred())

			client.Close()

			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		})

		It("provides a bearer token to the CC and gets the process guid", func() {
			client, err := ssh.Dial("tcp", address, clientConfig)
			Expect(err).NotTo(HaveOccurred())

			client.Close()

			Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
		})

		It("acquires the lrp info from the BBS using the process guid from the CC", func() {
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
})

func VerifyProto(expected proto.Message) http.HandlerFunc {
	return ghttp.CombineHandlers(
		ghttp.VerifyContentType("application/x-protobuf"),

		func(w http.ResponseWriter, req *http.Request) {
			defer GinkgoRecover()
			body, err := ioutil.ReadAll(req.Body)
			Expect(err).ToNot(HaveOccurred())
			req.Body.Close()

			expectedType := reflect.TypeOf(expected)
			actualValuePtr := reflect.New(expectedType.Elem())

			actual, ok := actualValuePtr.Interface().(proto.Message)
			Expect(ok).To(BeTrue())

			err = proto.Unmarshal(body, actual)
			Expect(err).ToNot(HaveOccurred())

			Expect(actual).To(Equal(expected), "ProtoBuf Mismatch")
		},
	)
}

func RespondWithProto(message proto.Message) http.HandlerFunc {
	data, err := proto.Marshal(message)
	Expect(err).ToNot(HaveOccurred())

	var headers = make(http.Header)
	headers["Content-Type"] = []string{"application/x-protobuf"}
	return ghttp.RespondWith(200, string(data), headers)
}
