package authenticators_test

import (
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry-incubator/receptor/fake_receptor"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("CFAuthenticator", func() {
	var (
		authenticator   *authenticators.CFAuthenticator
		logger          *lagertest.TestLogger
		ccClient        *http.Client
		ccClientTimeout time.Duration
		receptorClient  *fake_receptor.FakeClient

		permissions *ssh.Permissions
		err         error

		metadata *fake_ssh.FakeConnMetadata
		password []byte

		fakeCC *ghttp.Server
		ccURL  string
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		ccClientTimeout = 100 * time.Millisecond
		ccClient = &http.Client{Timeout: ccClientTimeout}
		receptorClient = new(fake_receptor.FakeClient)

		metadata = &fake_ssh.FakeConnMetadata{}

		fakeCC = ghttp.NewServer()
		ccURL = fakeCC.URL()
	})

	JustBeforeEach(func() {
		authenticator = authenticators.NewCFAuthenticator(logger, ccClient, ccURL, receptorClient)
		permissions, err = authenticator.Authenticate(metadata, password)
	})

	Describe("Authenticate", func() {
		var (
			expectedResponse   *authenticators.AppResponse
			responseCode       int
			expectedRoute      routes.SSHRoute
			desiredLRPResponse receptor.DesiredLRPResponse
			actualLRPResponse  receptor.ActualLRPResponse
		)

		BeforeEach(func() {
			metadata.UserReturns("cf:app-guid/1")
			password = []byte("bearer token")

			expectedResponse = &authenticators.AppResponse{
				Metadata: authenticators.AppMetadata{
					Guid: "app-guid",
				},
				Entity: authenticators.AppEntity{
					AllowSSH: true,
					Diego:    true,
					Version:  "app-version",
				},
			}
			responseCode = http.StatusOK

			fakeCC.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/v2/apps/app-guid"),
					ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
					ghttp.RespondWithJSONEncodedPtr(&responseCode, expectedResponse),
				),
			)

			expectedRoute = routes.SSHRoute{
				ContainerPort:   1111,
				PrivateKey:      "pem-encoded-key",
				HostFingerprint: "host-fingerprint",
				User:            "user",
				Password:        "password",
			}

			diegoSSHRoutePayload, err := json.Marshal(expectedRoute)
			Ω(err).ShouldNot(HaveOccurred())

			diegoSSHRouteMessage := json.RawMessage(diegoSSHRoutePayload)

			desiredLRPResponse = receptor.DesiredLRPResponse{
				ProcessGuid: "app-guid-app-version",
				Instances:   2,
				Routes: receptor.RoutingInfo{
					routes.DIEGO_SSH: &diegoSSHRouteMessage,
				},
			}

			actualLRPResponse = receptor.ActualLRPResponse{
				ProcessGuid:  "app-guid-app-version",
				Index:        0,
				InstanceGuid: "some-instance-guid",
				Address:      "1.2.3.4",
				Ports: []receptor.PortMapping{
					{ContainerPort: 1111, HostPort: 3333},
				},
			}

			receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLRPResponse, nil)
			receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
		})

		Context("when a client has inavlid username or password", func() {
			Context("and the guid is malformed", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:%X%FF/1")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidRequestErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("and the password is not a bearer token", func() {
				BeforeEach(func() {
					password = []byte("bearer")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidCredentialsErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("when the index is not an integer", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid/jim")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidCredentialsErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("when the username is malformed", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidCredentialsErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("when the index is too big", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid/" + strconv.FormatInt(int64(math.MaxInt64), 10) + "0")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidCredentialsErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("when the user realm is not cf", func() {
				BeforeEach(func() {
					metadata.UserReturns("diego:1234")
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidDomainErr))
				})
			})
		})

		Context("when a client has valid username and password", func() {
			It("fetches the app from CC using the bearer token", func() {
				Ω(err).ShouldNot(HaveOccurred())
				Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
			})

			It("gets information about the desired lrp referenced in the username", func() {
				Ω(receptorClient.GetDesiredLRPCallCount()).Should(Equal(1))
				Ω(receptorClient.GetDesiredLRPArgsForCall(0)).Should(Equal("app-guid-app-version"))
			})

			It("gets information about the the actual lrp from the username", func() {
				Ω(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).Should(Equal(1))

				guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
				Ω(guid).Should(Equal("app-guid-app-version"))
				Ω(index).Should(Equal(1))
			})

			It("saves container information in the critical options of the permissions", func() {
				expectedConfig := `{
								"address": "1.2.3.4:3333",
								"host_fingerprint": "host-fingerprint",
								"private_key": "pem-encoded-key",
								"user": "user",
								"password": "password"
							}`

				Ω(permissions).ShouldNot(BeNil())
				Ω(permissions.CriticalOptions).ShouldNot(BeNil())
				Ω(permissions.CriticalOptions["proxy-target-config"]).Should(MatchJSON(expectedConfig))
			})

			Context("and fetching the app from cc returns a non-200 status code", func() {
				BeforeEach(func() {
					responseCode = http.StatusInternalServerError
					expectedResponse = &authenticators.AppResponse{}
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.FetchAppFailedErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
				})
			})

			Context("and the application is not a Diego application", func() {
				BeforeEach(func() {
					expectedResponse.Entity.Diego = false
				})

				It("fails authentication", func() {
					Ω(err).Should(Equal(authenticators.NotDiegoErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
				})
			})

			Context("and allow_ssh is false", func() {
				BeforeEach(func() {
					expectedResponse.Entity.AllowSSH = false
				})

				It("fails authentication", func() {
					Ω(err).Should(Equal(authenticators.SSHDisabledErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
				})
			})

			Context("and the response cannot be parsed", func() {
				BeforeEach(func() {
					fakeCC.SetHandler(0, ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/v2/apps/app-guid"),
						ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
						ghttp.RespondWith(http.StatusOK, "{{"),
					))
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidCCResponse))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
				})
			})

			Context("and fetching the app from cc times out", func() {
				BeforeEach(func() {
					fakeCC.SetHandler(0, func(w http.ResponseWriter, req *http.Request) {
						time.Sleep(ccClientTimeout * 2)
						w.Write([]byte(`[]`))
					})
				})

				It("fails to authenticate", func() {
					Ω(err).Should(BeAssignableToTypeOf(&url.Error{}))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(1))
				})
			})

			Context("and the CC url is misconfigured", func() {
				BeforeEach(func() {
					ccURL = "http://%FF"
				})

				It("fails to authenticate", func() {
					Ω(err).Should(Equal(authenticators.InvalidRequestErr))
					Ω(fakeCC.ReceivedRequests()).Should(HaveLen(0))
				})
			})

			Context("when getting the desired LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.GetDesiredLRPReturns(receptor.DesiredLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Ω(err).Should(Equal(&receptor.Error{}))
				})
			})

			Context("when getting the actual LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Ω(err).Should(Equal(&receptor.Error{}))
				})
			})

			Context("when the container port cannot be found", func() {
				BeforeEach(func() {
					actualLRPResponse.Ports = []receptor.PortMapping{}
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLRPResponse, nil)
				})

				It("returns an empty permission reference", func() {
					Ω(permissions).Should(Equal(&ssh.Permissions{}))
				})
			})

			Context("when the ssh route is misconfigured", func() {
				Context("when the desired LRP does not include routes", func() {
					BeforeEach(func() {
						desiredLRPResponse.Routes = nil
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(err).Should(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the desired LRP does not include an SSH route", func() {
					BeforeEach(func() {
						delete(desiredLRPResponse.Routes, routes.DIEGO_SSH)
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(err).Should(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the ssh route fails to unmarshal", func() {
					BeforeEach(func() {
						message := json.RawMessage([]byte(`{,:`))
						desiredLRPResponse.Routes[routes.DIEGO_SSH] = &message
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(err).Should(HaveOccurred())
					})
				})
			})
		})
	})

	Describe("Realm", func() {
		It("is cf", func() {
			Ω(authenticator.Realm()).Should(Equal("cf"))
		})
	})
})
