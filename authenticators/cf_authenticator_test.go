package authenticators_test

import (
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators/fake_authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("CFAuthenticator", func() {
	var (
		authenticator      *authenticators.CFAuthenticator
		logger             *lagertest.TestLogger
		httpClient         *http.Client
		httpClientTimeout  time.Duration
		permissionsBuilder *fake_authenticators.FakePermissionsBuilder

		permissions *ssh.Permissions
		authenErr   error

		metadata *fake_ssh.FakeConnMetadata
		password []byte

		fakeCC  *ghttp.Server
		fakeUAA *ghttp.Server
		ccURL   string
		uaaURL  string
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		httpClientTimeout = time.Second
		httpClient = &http.Client{Timeout: httpClientTimeout}

		permissionsBuilder = &fake_authenticators.FakePermissionsBuilder{}
		permissionsBuilder.BuildReturns(&ssh.Permissions{}, nil)

		metadata = &fake_ssh.FakeConnMetadata{}

		fakeCC = ghttp.NewServer()
		ccURL = fakeCC.URL()

		fakeUAA = ghttp.NewServer()
		uaaURL = fakeUAA.URL()
	})

	JustBeforeEach(func() {
		authenticator = authenticators.NewCFAuthenticator(logger, httpClient, ccURL, uaaURL, permissionsBuilder)
		permissions, authenErr = authenticator.Authenticate(metadata, password)
	})

	Describe("UserRegexp", func() {
		var regexp *regexp.Regexp

		BeforeEach(func() {
			regexp = authenticator.UserRegexp()
		})

		It("matches diego patterns", func() {
			Expect(regexp.MatchString("cf:guid/0")).To(BeTrue())
			Expect(regexp.MatchString("cf:123-abc-def/00")).To(BeTrue())
			Expect(regexp.MatchString("cf:guid/99")).To(BeTrue())
		})

		It("does not match other patterns", func() {
			Expect(regexp.MatchString("cf:00")).To(BeFalse())
			Expect(regexp.MatchString("cf:/00")).To(BeFalse())
			Expect(regexp.MatchString("diego:guid/0")).To(BeFalse())
			Expect(regexp.MatchString("diego:guid/99")).To(BeFalse())
			Expect(regexp.MatchString("user@guid/0")).To(BeFalse())
		})
	})

	Describe("Authenticate", func() {
		const expectedOneTimeCode = "abc123"

		var (
			uaaTokenResponse     *authenticators.UAAAuthTokenResponse
			uaaTokenResponseCode int

			sshAccessResponse     *authenticators.AppSSHResponse
			sshAccessResponseCode int
		)

		BeforeEach(func() {
			metadata.UserReturns("cf:app-guid/1")
			password = []byte("bearer token")

			uaaTokenResponseCode = http.StatusOK
			uaaTokenResponse = &authenticators.UAAAuthTokenResponse{
				AccessToken: "token",
				TokenType:   "bearer",
			}
			sshAccessResponseCode = http.StatusOK
			sshAccessResponse = &authenticators.AppSSHResponse{
				ProcessGuid: "app-guid-app-version",
			}

			fakeUAA.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyFormKV("grant_type", "authorization_code"),
					ghttp.VerifyFormKV("code", expectedOneTimeCode),
					ghttp.RespondWithJSONEncodedPtr(&uaaTokenResponseCode, uaaTokenResponse),
				),
			)

			fakeCC.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
					ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
					ghttp.RespondWithJSONEncodedPtr(&sshAccessResponseCode, sshAccessResponse),
				),
			)
		})

		It("fetches the app from CC using the bearer token", func() {
			Expect(authenErr).NotTo(HaveOccurred())
			Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(0))
		})

		It("builds permissions from the process guid of the app", func() {
			Expect(permissionsBuilder.BuildCallCount()).To(Equal(1))

			guid, index, metadata := permissionsBuilder.BuildArgsForCall(0)
			Expect(guid).To(Equal("app-guid-app-version"))
			Expect(index).To(Equal(1))
			Expect(metadata).To(Equal(metadata))
		})

		Context("when the client password is not a bearer token", func() {
			BeforeEach(func() {
				password = []byte(expectedOneTimeCode)
			})

			It("attempts to use the password as a one time code with the UAA", func() {
				Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})

			Context("when the token exchange fails", func() {
				BeforeEach(func() {
					uaaTokenResponseCode = http.StatusBadRequest
				})

				It("fails to authenticate", func() {
					Expect(authenErr).To(Equal(authenticators.AuthenticationFailedErr))
					Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
				})
			})
		})

		Context("when the app guid is malformed", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:%X%FF/1")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidRequestErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the index is not an integer", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:app-guid/jim")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the username is missing an index", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:app-guid")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the index is too big", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:app-guid/" + strconv.FormatInt(int64(math.MaxInt64), 10) + "0")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the cc ssh_access check returns a non-200 status code", func() {
			BeforeEach(func() {
				sshAccessResponseCode = http.StatusInternalServerError
				sshAccessResponse = &authenticators.AppSSHResponse{}
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.FetchAppFailedErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})
		})

		Context("when the cc ssh_access response cannot be parsed", func() {
			BeforeEach(func() {
				fakeCC.SetHandler(0, ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/internal/apps/app-guid/ssh_access"),
					ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer token"}}),
					ghttp.RespondWith(http.StatusOK, "{{"),
				))
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCCResponse))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})
		})

		Context("the the cc ssh_access check times out", func() {
			BeforeEach(func() {
				ccTempClientTimeout := httpClientTimeout
				fakeCC.SetHandler(0, func(w http.ResponseWriter, req *http.Request) {
					time.Sleep(ccTempClientTimeout * 2)
					w.Write([]byte(`[]`))
				})
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(BeAssignableToTypeOf(&url.Error{}))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})
		})

		Context("when the cc url is misconfigured", func() {
			BeforeEach(func() {
				ccURL = "http://%FF"
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidRequestErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})
	})
})
