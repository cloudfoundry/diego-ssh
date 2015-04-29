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
			expectedResponse   *authenticators.AppSSHResponse
			responseCode       int
			expectedRoute      routes.SSHRoute
			desiredLRPResponse receptor.DesiredLRPResponse
			actualLRPResponse  receptor.ActualLRPResponse
		)

		BeforeEach(func() {
			metadata.UserReturns("cf:app-guid/1")
			password = []byte("bearer token")

			expectedResponse = &authenticators.AppSSHResponse{
				ProcessGuid: "app-guid-app-version",
			}
			responseCode = http.StatusOK

			fakeCC.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
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
			Expect(err).NotTo(HaveOccurred())

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
					Expect(err).To(Equal(authenticators.InvalidRequestErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})

			Context("when the index is not an integer", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid/jim")
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidCredentialsErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})

			Context("when the username is malformed", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid")
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidCredentialsErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})

			Context("when the index is too big", func() {
				BeforeEach(func() {
					metadata.UserReturns("cf:app-guid/" + strconv.FormatInt(int64(math.MaxInt64), 10) + "0")
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidCredentialsErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})

			Context("when the user realm is not cf", func() {
				BeforeEach(func() {
					metadata.UserReturns("diego:1234")
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidDomainErr))
				})
			})
		})

		Context("when a client has valid username and password", func() {
			It("fetches the app from CC using the bearer token", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})

			It("gets information about the desired lrp referenced in the username", func() {
				Expect(receptorClient.GetDesiredLRPCallCount()).To(Equal(1))
				Expect(receptorClient.GetDesiredLRPArgsForCall(0)).To(Equal("app-guid-app-version"))
			})

			It("gets information about the the actual lrp from the username", func() {
				Expect(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).To(Equal(1))

				guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
				Expect(guid).To(Equal("app-guid-app-version"))
				Expect(index).To(Equal(1))
			})

			It("saves container information in the critical options of the permissions", func() {
				expectedConfig := `{
								"address": "1.2.3.4:3333",
								"host_fingerprint": "host-fingerprint",
								"private_key": "pem-encoded-key",
								"user": "user",
								"password": "password"
							}`

				Expect(permissions).NotTo(BeNil())
				Expect(permissions.CriticalOptions).NotTo(BeNil())
				Expect(permissions.CriticalOptions["proxy-target-config"]).To(MatchJSON(expectedConfig))
			})

			Context("and fetching the ssh_access from cc returns a non-200 status code", func() {
				BeforeEach(func() {
					responseCode = http.StatusInternalServerError
					expectedResponse = &authenticators.AppSSHResponse{}
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.FetchAppFailedErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
				})
			})

			Context("and the response cannot be parsed", func() {
				BeforeEach(func() {
					fakeCC.SetHandler(0, ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
						ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
						ghttp.RespondWith(http.StatusOK, "{{"),
					))
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidCCResponse))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
				})
			})

			Context("and fetching the ssh_access from cc times out", func() {
				BeforeEach(func() {
					ccTempClientTimeout := ccClientTimeout
					fakeCC.SetHandler(0, func(w http.ResponseWriter, req *http.Request) {
						time.Sleep(ccTempClientTimeout * 2)
						w.Write([]byte(`[]`))
					})
				})

				It("fails to authenticate", func() {
					Expect(err).To(BeAssignableToTypeOf(&url.Error{}))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
				})
			})

			Context("and the CC url is misconfigured", func() {
				BeforeEach(func() {
					ccURL = "http://%FF"
				})

				It("fails to authenticate", func() {
					Expect(err).To(Equal(authenticators.InvalidRequestErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})

			Context("when getting the desired LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.GetDesiredLRPReturns(receptor.DesiredLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Expect(err).To(Equal(&receptor.Error{}))
				})
			})

			Context("when getting the actual LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Expect(err).To(Equal(&receptor.Error{}))
				})
			})

			Context("when the container port cannot be found", func() {
				BeforeEach(func() {
					actualLRPResponse.Ports = []receptor.PortMapping{}
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLRPResponse, nil)
				})

				It("returns an empty permission reference", func() {
					Expect(permissions).To(Equal(&ssh.Permissions{}))
				})
			})

			Context("when the ssh route is misconfigured", func() {
				Context("when the desired LRP does not include routes", func() {
					BeforeEach(func() {
						desiredLRPResponse.Routes = nil
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Expect(err).To(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the desired LRP does not include an SSH route", func() {
					BeforeEach(func() {
						delete(desiredLRPResponse.Routes, routes.DIEGO_SSH)
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Expect(err).To(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the ssh route fails to unmarshal", func() {
					BeforeEach(func() {
						message := json.RawMessage([]byte(`{,:`))
						desiredLRPResponse.Routes[routes.DIEGO_SSH] = &message
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Expect(err).To(HaveOccurred())
					})
				})
			})
		})
	})

	Describe("Realm", func() {
		It("is cf", func() {
			Expect(authenticator.Realm()).To(Equal("cf"))
		})
	})
})
