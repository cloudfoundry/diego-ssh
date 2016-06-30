package authenticators_test

import (
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"code.cloudfoundry.org/diego-ssh/authenticators"
	"code.cloudfoundry.org/diego-ssh/authenticators/fake_authenticators"
	"code.cloudfoundry.org/diego-ssh/test_helpers/fake_ssh"
	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("CFAuthenticator", func() {
	var (
		authenticator      *authenticators.CFAuthenticator
		logger             *lagertest.TestLogger
		httpClient         *http.Client
		httpClientTimeout  time.Duration
		permissionsBuilder *fake_authenticators.FakePermissionsBuilder

		authenErr error

		metadata *fake_ssh.FakeConnMetadata
		password []byte

		fakeCC      *ghttp.Server
		fakeUAA     *ghttp.Server
		ccURL       string
		uaaTokenURL string
		uaaUsername string
		uaaPassword string
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
		u, err := url.Parse(fakeUAA.URL())
		Expect(err).NotTo(HaveOccurred())
		uaaUsername = "diego-ssh"
		uaaPassword = "fake-diego-ssh-secret-$\"^&'"

		u.Path = "/oauth/token"
		uaaTokenURL = u.String()
	})

	JustBeforeEach(func() {
		authenticator = authenticators.NewCFAuthenticator(logger, httpClient, ccURL, uaaTokenURL, uaaUsername, uaaPassword, permissionsBuilder)
		_, authenErr = authenticator.Authenticate(metadata, password)
	})

	Describe("UserRegexp", func() {
		var regexp *regexp.Regexp

		BeforeEach(func() {
			regexp = authenticator.UserRegexp()
		})

		It("matches cf:<app-guid>/<instance> patterns", func() {
			Expect(regexp.MatchString("cf:986fedf8-6b74-45af-827c-a4464e6aa05c/00")).To(BeTrue())
			Expect(regexp.MatchString("cf:986FEDF8-6B74-45AF-827C-A4464E6AA05C/00")).To(BeTrue())
		})

		It("does not match other patterns", func() {
			Expect(regexp.MatchString("cf:hhhhhhhh-6b74-45af-827c-a4464e6aa05c/00")).To(BeFalse())
			Expect(regexp.MatchString("cf:986fedf81-6b74-45af-827c-a4464e6aa05c/00")).To(BeFalse())
			Expect(regexp.MatchString("cf:986fedf8-6b74-45af-827c-a4464e6aa05c/")).To(BeFalse())
			Expect(regexp.MatchString("cf:guid/1")).To(BeFalse())
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
			metadata.UserReturns("cf:1e051b88-a210-40b7-bcca-df645b24b634/1")
			password = []byte(expectedOneTimeCode)

			uaaTokenResponseCode = http.StatusOK
			uaaTokenResponse = &authenticators.UAAAuthTokenResponse{
				AccessToken: "exchanged-token",
				TokenType:   "bearer",
			}

			fakeUAA.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/oauth/token"),
					ghttp.VerifyBasicAuth("diego-ssh", "fake-diego-ssh-secret-$\"^&'"),
					ghttp.VerifyFormKV("grant_type", "authorization_code"),
					ghttp.VerifyFormKV("code", expectedOneTimeCode),
					ghttp.RespondWithJSONEncodedPtr(&uaaTokenResponseCode, uaaTokenResponse),
				),
			)

			sshAccessResponseCode = http.StatusOK
			sshAccessResponse = &authenticators.AppSSHResponse{
				ProcessGuid: "app-guid-app-version",
			}

			fakeCC.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/internal/apps/1e051b88-a210-40b7-bcca-df645b24b634/ssh_access/1"),
					ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer exchanged-token"}}),
					ghttp.RespondWithJSONEncodedPtr(&sshAccessResponseCode, sshAccessResponse),
				),
			)
		})

		It("uses the client password as a one time code with the UAA", func() {
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		})

		It("fetches the app from CC using the bearer token", func() {
			Expect(authenErr).NotTo(HaveOccurred())
			Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
		})

		It("builds permissions from the process guid of the app", func() {
			Expect(permissionsBuilder.BuildCallCount()).To(Equal(1))

			_, guid, index, metadata := permissionsBuilder.BuildArgsForCall(0)
			Expect(guid).To(Equal("app-guid-app-version"))
			Expect(index).To(Equal(1))
			Expect(metadata).To(Equal(metadata))
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

		Context("when the app guid is malformed", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:%X%FF/1")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the index is not an integer", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:1e051b88-a210-40b7-bcca-df645b24b634/jim")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the username is missing an index", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:1e051b88-a210-40b7-bcca-df645b24b634")
			})

			It("fails to authenticate", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidCredentialsErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})

		Context("when the index is too big", func() {
			BeforeEach(func() {
				metadata.UserReturns("cf:1e051b88-a210-40b7-bcca-df645b24b634/" + strconv.FormatInt(int64(math.MaxInt64), 10) + "0")
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
				fakeCC.RouteToHandler("GET", "/internal/apps/1e051b88-a210-40b7-bcca-df645b24b634/ssh_access/1", ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/internal/apps/1e051b88-a210-40b7-bcca-df645b24b634/ssh_access/1"),
					ghttp.VerifyHeader(http.Header{"Authorization": []string{"bearer exchanged-token"}}),
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
				fakeCC.RouteToHandler("GET", "/internal/apps/1e051b88-a210-40b7-bcca-df645b24b634/ssh_access/1",
					func(w http.ResponseWriter, req *http.Request) {
						time.Sleep(ccTempClientTimeout * 2)
						w.Write([]byte(`[]`))
					},
				)
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
				Expect(authenErr).To(HaveOccurred())
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})
	})
})
