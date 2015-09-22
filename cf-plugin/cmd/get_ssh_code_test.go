package cmd_test

import (
	"bytes"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/cmd"
	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/credential/credential_fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetSSHCode", func() {
	var fakeCredFactory *credential_fakes.FakeCredentialFactory

	BeforeEach(func() {
		fakeCredFactory = &credential_fakes.FakeCredentialFactory{}
	})

	It("validates the command name", func() {
		err := cmd.GetSSHCode([]string{"bogus-name"}, fakeCredFactory, nil)
		Expect(err).To(MatchError("Invalid usage\n" + cmd.GetSSHCodeUsage))
	})

	It("does not accept any arugments", func() {
		err := cmd.GetSSHCode([]string{"get-ssh-code", "bogus-argument"}, fakeCredFactory, nil)
		Expect(err).To(MatchError("Invalid usage\n" + cmd.GetSSHCodeUsage))
	})

	It("gets the authorization code from the credential factory", func() {
		fakeCredFactory.AuthorizationCodeReturns("xyxpdq", nil)

		writer := &bytes.Buffer{}
		err := cmd.GetSSHCode([]string{"get-ssh-code"}, fakeCredFactory, writer)
		Expect(err).NotTo(HaveOccurred())

		Expect(writer.String()).To(Equal("xyxpdq\n"))
	})
})
