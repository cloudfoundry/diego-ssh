package credential_test

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info/info_fakes"
	"github.com/cloudfoundry/cli/plugin/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Credential", func() {
	var (
		fakeCliConnection *fakes.FakeCliConnection
		fakeInfoFactory   *info_fakes.FakeInfoFactory
		credFactory       credential.CredentialFactory
	)

	BeforeEach(func() {
		fakeCliConnection = &fakes.FakeCliConnection{}
		fakeCliConnection.IsSSLDisabledReturns(true, nil)
		fakeInfoFactory = &info_fakes.FakeInfoFactory{}
	})

	JustBeforeEach(func() {
		credFactory = credential.NewCredentialFactory(fakeCliConnection, fakeInfoFactory)
	})

	Describe("AuthorizationToken", func() {
		It("returns a credential token", func() {
			fakeCliConnection.AccessTokenReturns("bearer lives_in_a_man_cave", nil)

			cred, err := credFactory.AuthorizationToken()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeCliConnection.CliCommandWithoutTerminalOutputCallCount()).To(Equal(1))
			Expect(fakeCliConnection.CliCommandWithoutTerminalOutputArgsForCall(0)).To(ConsistOf("oauth-token"))
			Expect(fakeCliConnection.AccessTokenCallCount()).To(Equal(1))
			Expect(cred).To(Equal("bearer lives_in_a_man_cave"))
		})

		It("returns the error when refreshing the access token fails", func() {
			fakeCliConnection.CliCommandWithoutTerminalOutputReturns([]string{}, errors.New("woops"))

			_, err := credFactory.AuthorizationToken()
			Expect(err).To(MatchError("woops"))

			Expect(fakeCliConnection.CliCommandWithoutTerminalOutputCallCount()).To(Equal(1))
			Expect(fakeCliConnection.AccessTokenCallCount()).To(Equal(0))
		})

		It("returns the error when getting the access token fails", func() {
			fakeCliConnection.AccessTokenReturns("", errors.New("woops"))

			_, err := credFactory.AuthorizationToken()
			Expect(err).To(MatchError("woops"))

			Expect(fakeCliConnection.AccessTokenCallCount()).To(Equal(1))
		})
	})

	Describe("AuthorizationCode", func() {
		var v2Info info.Info
		var fakeUAA *ghttp.Server

		BeforeEach(func() {
			fakeCliConnection.AccessTokenReturns("bearer client-bearer-token", nil)

			fakeUAA = ghttp.NewTLSServer()
			v2Info = info.Info{
				SSHOAuthClient: "ssh-oauth-client-id",
				TokenEndpoint:  fakeUAA.URL(),
			}
			fakeInfoFactory.GetReturns(v2Info, nil)

			fakeUAA.RouteToHandler("GET", "/oauth/authorize", ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/oauth/authorize"),
				ghttp.VerifyFormKV("response_type", "code"),
				ghttp.VerifyFormKV("client_id", "ssh-oauth-client-id"),
				ghttp.VerifyFormKV("grant_type", "authorization_code"),
				ghttp.VerifyHeaderKV("authorization", "bearer client-bearer-token"),
				ghttp.RespondWith(http.StatusFound, "", http.Header{
					"Location": []string{"https://uaa.example.com/login?code=abc123"},
				}),
			))
		})

		It("gets the access code from the token endpoint", func() {
			code, err := credFactory.AuthorizationCode()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
			Expect(code).To(Equal("abc123"))
		})

		It("returns an error when the uaa certificate is not valid and certificate validation is enabled", func() {
			fakeCliConnection.IsSSLDisabledReturns(false, nil)

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(HaveOccurred())

			urlErr, ok := err.(*url.Error)
			Expect(ok).To(BeTrue())
			Expect(urlErr.Err).To(MatchError(ContainSubstring("signed by unknown authority")))

			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(0))
		})

		It("returns the error from the info factory when getting /v2/info fails", func() {
			var expectedErr = errors.New("boom")
			fakeInfoFactory.GetReturns(info.Info{}, expectedErr)

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(Equal(expectedErr))
		})

		It("returns the error from the cli plugin when getting the access token fails", func() {
			var expectedErr = errors.New("boom")
			fakeCliConnection.AccessTokenReturns("", expectedErr)

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(Equal(expectedErr))
		})

		It("returns an error when the endpoint url cannot be parsed", func() {
			fakeInfoFactory.GetReturns(info.Info{
				SSHOAuthClient: "ssh-oauth-client-id",
				TokenEndpoint:  ":goober#swallow?yak",
			}, nil)

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(HaveOccurred())
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(0))
		})

		It("returns an error when the request to the authorization server fails", func() {
			fakeInfoFactory.GetReturns(info.Info{
				SSHOAuthClient: "ssh-oauth-client-id",
				TokenEndpoint:  "http://0.0.0.0", // invalid address
			}, nil)

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when the authorization server does not redirect", func() {
			fakeUAA.RouteToHandler("GET", "/oauth/authorize", ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/oauth/authorize"),
				ghttp.RespondWith(http.StatusOK, ""),
			))

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(MatchError("Authorization server did not redirect with one time code"))
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		})

		It("returns an error when the redirect URL does not contain a code", func() {
			fakeUAA.RouteToHandler("GET", "/oauth/authorize", ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/oauth/authorize"),
				ghttp.RespondWith(http.StatusFound, "", http.Header{
					"Location": []string{"https://uaa.example.com/login"},
				}),
			))

			_, err := credFactory.AuthorizationCode()
			Expect(err).To(MatchError("Unable to acquire one time code from authorization response"))
			Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		})
	})
})
