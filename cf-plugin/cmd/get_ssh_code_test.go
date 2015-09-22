package cmd_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/cmd"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential/credential_fakes"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info/info_fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("GetSSHCode", func() {
	var (
		fakeInfoFactory *info_fakes.FakeInfoFactory
		fakeCredFactory *credential_fakes.FakeCredentialFactory
		v2Info          info.Info
		fakeUAA         *ghttp.Server
	)

	BeforeEach(func() {
		fakeUAA = ghttp.NewTLSServer()

		fakeCredFactory = &credential_fakes.FakeCredentialFactory{}
		cred := credential.Credential{
			Token: "bearer client-bearer-token",
		}
		fakeCredFactory.GetReturns(cred, nil)

		fakeInfoFactory = &info_fakes.FakeInfoFactory{}
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

	It("validates the command name", func() {
		err := cmd.GetSSHCode([]string{"bogus-name"}, fakeInfoFactory, fakeCredFactory, false, nil)
		Expect(err).To(MatchError("Invalid usage\n" + cmd.GetSSHCodeUsage))
	})

	It("does not accept any arugments", func() {
		err := cmd.GetSSHCode([]string{"get-ssh-code", "bogus-argument"}, fakeInfoFactory, fakeCredFactory, false, nil)
		Expect(err).To(MatchError("Invalid usage\n" + cmd.GetSSHCodeUsage))
	})

	It("gets the access code from the token endpoint", func() {
		writer := &bytes.Buffer{}
		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, writer)
		Expect(err).NotTo(HaveOccurred())

		Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
		Expect(writer.String()).To(Equal("abc123\n"))
	})

	It("returns an error when the uaa certificate is not valid and certificate validation is enabled", func() {
		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, false, nil)
		Expect(err).To(HaveOccurred())

		urlErr, ok := err.(*url.Error)
		Expect(ok).To(BeTrue())
		Expect(urlErr.Err).To(MatchError(ContainSubstring("signed by unknown authority")))

		Expect(fakeUAA.ReceivedRequests()).To(HaveLen(0))
	})

	It("returns the error from the info factory when getting /v2/info fails", func() {
		var expectedErr = errors.New("boom")
		fakeInfoFactory.GetReturns(info.Info{}, expectedErr)
		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
		Expect(err).To(Equal(expectedErr))
	})

	It("returns the error from the cred factory when getting the credential token fails", func() {
		var expectedErr = errors.New("boom")
		fakeCredFactory.GetReturns(credential.Credential{}, expectedErr)

		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
		Expect(err).To(Equal(expectedErr))
	})

	It("returns an error when the endpoint url cannot be parsed", func() {
		fakeInfoFactory.GetReturns(info.Info{
			SSHOAuthClient: "ssh-oauth-client-id",
			TokenEndpoint:  ":goober#swallow?yak",
		}, nil)

		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when the authorization request fails", func() {
		fakeInfoFactory.GetReturns(info.Info{
			SSHOAuthClient: "ssh-oauth-client-id",
			TokenEndpoint:  "http://0.0.0.0",
		}, nil)

		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when the authorization server does not redirect", func() {
		fakeUAA.RouteToHandler("GET", "/oauth/authorize", ghttp.CombineHandlers(
			ghttp.VerifyRequest("GET", "/oauth/authorize"),
			ghttp.RespondWith(http.StatusOK, ""),
		))

		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
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

		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeInfoFactory, fakeCredFactory, true, nil)
		Expect(err).To(MatchError("Unable to acquire one time code from authorization response"))
		Expect(fakeUAA.ReceivedRequests()).To(HaveLen(1))
	})

})
