package authenticators_test

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators/fake_authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("UaaAuthenticator", func() {
	var (
		authenticator    *authenticators.UAAAuthenticator
		logger           *lagertest.TestLogger
		uaaClient        *http.Client
		uaaClientTimeout time.Duration

		fakeUAA *ghttp.Server
		uaaURL  string
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		uaaClientTimeout = time.Second
		uaaClient = &http.Client{Timeout: uaaClientTimeout}

		fakeUAA = ghttp.NewServer()
		u, err := url.Parse(fakeUAA.URL())
		Expect(err).NotTo(HaveOccurred())
		u.User = url.UserPassword("uaa-client", "uaa-client-password")
		uaaURL = u.String()
	})

	Describe("Authenticate", func() {
		var (
			permissions         *ssh.Permissions
			authenErr           error
			metadata            *fake_ssh.FakeConnMetadata
			password            []byte
			ccAccessChecker     *fake_authenticators.FakeCCAccessChecker
			permissionsBuilder  *fake_authenticators.FakePermissionsBuilder
			expectedPermissions *ssh.Permissions

			uaaTokenResponseCode int
			uaaTokenResponse     interface{}
		)

		BeforeEach(func() {
			metadata = &fake_ssh.FakeConnMetadata{}
			metadata.UserReturns("ssh-client@app-guid/1")
			password = []byte("ssh-client-password")
			expectedPermissions = &ssh.Permissions{
				CriticalOptions: map[string]string{"expected": "permission"},
			}

			ccAccessChecker = &fake_authenticators.FakeCCAccessChecker{}
			ccAccessChecker.CheckAccessReturns("app-guid-app-version", nil)

			permissionsBuilder = &fake_authenticators.FakePermissionsBuilder{}
			permissionsBuilder.BuildReturns(expectedPermissions, nil)

			uaaTokenResponseCode = http.StatusOK
			uaaTokenResponse = authenticators.UAAAuthTokenResponse{
				AccessToken: "access-token",
				TokenType:   "token-type",
			}

			fakeUAA.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("POST", "/oauth/token"),
					ghttp.VerifyBasicAuth("uaa-client", "uaa-client-password"),
					ghttp.VerifyContentType("application/x-www-form-urlencoded"),
					ghttp.VerifyHeaderKV("accept", "application/json"),
					ghttp.VerifyFormKV("grant_type", "password"),
					ghttp.VerifyFormKV("username", "ssh-client"),
					ghttp.VerifyFormKV("password", "ssh-client-password"),
					ghttp.RespondWithJSONEncodedPtr(&uaaTokenResponseCode, &uaaTokenResponse),
				),
			)
		})

		JustBeforeEach(func() {
			authenticator = authenticators.NewUAAAuthenticator(logger, uaaClient, uaaURL, ccAccessChecker, permissionsBuilder)
			permissions, authenErr = authenticator.Authenticate(metadata, password)
		})

		It("fetches a bearer token from the UAA and uses it to check access", func() {
			Expect(authenErr).NotTo(HaveOccurred())
			Expect(permissions).To(Equal(expectedPermissions))
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		})

		It("uses the bearer token from the UAA when performing the access control check", func() {
			Expect(ccAccessChecker.CheckAccessCallCount()).To(Equal(1))
			l, guid, token := ccAccessChecker.CheckAccessArgsForCall(0)
			Expect(l).NotTo(BeNil())
			Expect(guid).To(Equal("app-guid"))
			Expect(token).To(Equal("token-type access-token"))
		})

		It("uses the process guid from the access control check to build permissions", func() {
			Expect(permissionsBuilder.BuildCallCount()).To(Equal(1))

			pg, index, cmd := permissionsBuilder.BuildArgsForCall(0)
			Expect(pg).To(Equal("app-guid-app-version"))
			Expect(index).To(Equal(1))
			Expect(cmd).To(Equal(metadata))
		})

		Context("when the ssh user malformed", func() {
			BeforeEach(func() {
				metadata.UserReturns("ssh-client@app-guid")
			})

			It("returns an invalid user format error", func() {
				Expect(authenErr).To(Equal(authenticators.InvalidUserFormatErr))
			})
		})

		Context("when the uaa request fails", func() {
			BeforeEach(func() {
				uaaURL = "http://0.0.0.0:0"
			})

			It("returns an authentication failed error", func() {
				Expect(authenErr).To(Equal(authenticators.AuthenticationFailedErr))
			})
		})

		Context("when the uaa responds with a non-200 status code", func() {
			BeforeEach(func() {
				uaaTokenResponseCode = http.StatusUnauthorized
			})

			It("returns an authentication failed error", func() {
				Expect(authenErr).To(Equal(authenticators.AuthenticationFailedErr))
			})
		})

		Context("when the uaa response fails to unmarshal", func() {
			BeforeEach(func() {
				uaaTokenResponse = []byte{42}
			})

			It("returns an authentication failed error", func() {
				Expect(authenErr).To(Equal(authenticators.AuthenticationFailedErr))
			})
		})

		Context("when the cloud controller access check fails", func() {
			var ccError error

			BeforeEach(func() {
				ccError = errors.New("woops")
				ccAccessChecker.CheckAccessReturns("", ccError)
			})

			It("returns the access check error", func() {
				Expect(authenErr).To(Equal(ccError))
			})
		})

		Context("when building permissions fails", func() {
			var buildError error

			BeforeEach(func() {
				buildError = errors.New("woops")
				permissionsBuilder.BuildReturns(nil, buildError)
			})

			It("returns the error from the permission builder", func() {
				Expect(authenErr).To(Equal(buildError))
			})
		})
	})

	Describe("UserRegexp", func() {
		var regexp *regexp.Regexp

		BeforeEach(func() {
			regexp = authenticator.UserRegexp()
		})

		It("matches user@ patterns", func() {
			Expect(regexp.MatchString("user@guid/0")).To(BeTrue())
			Expect(regexp.MatchString("user@domain@guid/0")).To(BeTrue())
			Expect(regexp.MatchString("123@guid/0")).To(BeTrue())
			Expect(regexp.MatchString("123@domainguid/0")).To(BeTrue())
		})

		It("does not match other patterns", func() {
			Expect(regexp.MatchString("user@0")).To(BeFalse())
			Expect(regexp.MatchString("user@/0")).To(BeFalse())
			Expect(regexp.MatchString("user@/")).To(BeFalse())
			Expect(regexp.MatchString("@")).To(BeFalse())
			Expect(regexp.MatchString("@0")).To(BeFalse())
			Expect(regexp.MatchString("@/0")).To(BeFalse())
			Expect(regexp.MatchString("cf:00")).To(BeFalse())
			Expect(regexp.MatchString("diego:00")).To(BeFalse())
			Expect(regexp.MatchString("cf:/00")).To(BeFalse())
			Expect(regexp.MatchString("diego:/00")).To(BeFalse())
			Expect(regexp.MatchString("diego:guid/0")).To(BeFalse())
			Expect(regexp.MatchString("cf:guid/0")).To(BeFalse())
			Expect(regexp.MatchString("diego:guid/99")).To(BeFalse())
			Expect(regexp.MatchString("cf:guid/99")).To(BeFalse())
		})
	})
})
