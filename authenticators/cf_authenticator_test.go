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
		ccClient           *http.Client
		ccClientTimeout    time.Duration
		permissionsBuilder *fake_authenticators.FakePermissionsBuilder

		permissions *ssh.Permissions
		err         error

		metadata *fake_ssh.FakeConnMetadata
		password []byte

		fakeCC *ghttp.Server
		ccURL  string
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")

		ccClientTimeout = time.Second
		ccClient = &http.Client{Timeout: ccClientTimeout}

		permissionsBuilder = &fake_authenticators.FakePermissionsBuilder{}
		permissionsBuilder.BuildReturns(&ssh.Permissions{}, nil)

		metadata = &fake_ssh.FakeConnMetadata{}

		fakeCC = ghttp.NewServer()
		ccURL = fakeCC.URL()
	})

	Describe("Authenticate", func() {
		var (
			expectedResponse *authenticators.AppSSHResponse
			responseCode     int
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
		})

		JustBeforeEach(func() {
			authenticator = authenticators.NewCFAuthenticator(logger, ccClient, ccURL, permissionsBuilder)
			permissions, err = authenticator.Authenticate(metadata, password)
		})

		It("fetches the app from CC using the bearer token", func() {
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
		})

		It("builds permissions from the process guid of the app", func() {
			Expect(permissionsBuilder.BuildCallCount()).To(Equal(1))

			guid, index, metadata := permissionsBuilder.BuildArgsForCall(0)
			Expect(guid).To(Equal("app-guid-app-version"))
			Expect(index).To(Equal(1))
			Expect(metadata).To(Equal(metadata))
		})

		Context("when the app guid is malformed", func() {
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

		Context("when the username is missing an index", func() {
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

		Context("when the cc ssh_access check returns a non-200 status code", func() {
			BeforeEach(func() {
				responseCode = http.StatusInternalServerError
				expectedResponse = &authenticators.AppSSHResponse{}
			})

			It("fails to authenticate", func() {
				Expect(err).To(Equal(authenticators.FetchAppFailedErr))
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
				Expect(err).To(Equal(authenticators.InvalidCCResponse))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(1))
			})
		})

		Context("the the cc ssh_access check times out", func() {
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

		Context("when the cc url is misconfigured", func() {
			BeforeEach(func() {
				ccURL = "http://%FF"
			})

			It("fails to authenticate", func() {
				Expect(err).To(Equal(authenticators.InvalidRequestErr))
				Expect(fakeCC.ReceivedRequests()).To(HaveLen(0))
			})
		})
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
})
