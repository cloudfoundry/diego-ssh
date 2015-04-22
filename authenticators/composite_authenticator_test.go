package authenticators_test

import (
	"errors"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators/fake_authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("CompositeAuthenticator", func() {
	Describe("Authenticate", func() {
		var (
			authenticator *authenticators.CompositeAuthenticator
			auths         []authenticators.PasswordAuthenticator
			metadata      *fake_ssh.FakeConnMetadata
			password      []byte
		)

		BeforeEach(func() {
			auths = []authenticators.PasswordAuthenticator{}
			metadata = &fake_ssh.FakeConnMetadata{}
			password = []byte{}
		})

		JustBeforeEach(func() {
			authenticator = authenticators.NewCompositeAuthenticator(auths)
		})

		Context("when no authenticators are specified", func() {
			It("fails to authenticate", func() {
				_, err := authenticator.Authenticate(metadata, password)
				Ω(err).Should(MatchError("Invalid credentials"))
			})
		})

		Context("when one or more authenticator is specified", func() {
			var (
				authenticatorOne *fake_authenticators.FakePasswordAuthenticator
				authenticatorTwo *fake_authenticators.FakePasswordAuthenticator
			)

			BeforeEach(func() {
				authenticatorOne = &fake_authenticators.FakePasswordAuthenticator{}
				authenticatorTwo = &fake_authenticators.FakePasswordAuthenticator{}
				auths = append(auths, authenticatorOne, authenticatorTwo)
			})

			Context("and the first authenticator is matched by the connection metadata", func() {
				BeforeEach(func() {
					authenticatorOne.ShouldAuthenticateReturns(true)
					authenticatorTwo.ShouldAuthenticateReturns(false)
				})

				Context("and the authenticator successfully authenticates", func() {
					var permissions *ssh.Permissions

					BeforeEach(func() {
						permissions = &ssh.Permissions{}
						authenticatorOne.AuthenticateReturns(permissions, nil)
					})

					It("succeeds to authenticate", func() {
						perms, err := authenticator.Authenticate(metadata, password)

						Ω(err).ShouldNot(HaveOccurred())
						Ω(perms).Should(Equal(permissions))
					})
				})

				Context("and the authenticator fails to authenticate", func() {
					BeforeEach(func() {
						authenticatorOne.AuthenticateReturns(nil, errors.New("boom"))
					})

					It("fails to authenticate", func() {
						_, err := authenticator.Authenticate(metadata, password)
						Ω(err).Should(MatchError("boom"))
					})
				})

				It("does not attempt to authenticate with any further authenticators", func() {
					authenticator.Authenticate(metadata, password)
					Ω(authenticatorTwo.ShouldAuthenticateCallCount()).Should(Equal(0))
					Ω(authenticatorTwo.AuthenticateCallCount()).Should(Equal(0))
				})
			})

			Context("and the second authenticator fails to match the connection metadata", func() {
				BeforeEach(func() {
					authenticatorOne.ShouldAuthenticateReturns(false)
					authenticatorTwo.ShouldAuthenticateReturns(true)
				})

				It("attempts to authenticate with the second authenticator", func() {
					authenticator.Authenticate(metadata, password)
					Ω(authenticatorOne.ShouldAuthenticateCallCount()).Should(Equal(1))
					Ω(authenticatorOne.AuthenticateCallCount()).Should(Equal(0))
					Ω(authenticatorTwo.ShouldAuthenticateCallCount()).Should(Equal(1))
					Ω(authenticatorTwo.AuthenticateCallCount()).Should(Equal(1))
				})
			})

			Context("and no authenticators are matched by the connection metadata", func() {
				BeforeEach(func() {
					authenticatorOne.ShouldAuthenticateReturns(false)
					authenticatorTwo.ShouldAuthenticateReturns(false)
				})

				It("fails to authenticate", func() {
					_, err := authenticator.Authenticate(metadata, password)

					Ω(err).Should(MatchError("Invalid credentials"))
					Ω(authenticatorOne.ShouldAuthenticateCallCount()).Should(Equal(1))
					Ω(authenticatorTwo.ShouldAuthenticateCallCount()).Should(Equal(1))
					Ω(authenticatorOne.AuthenticateCallCount()).Should(Equal(0))
					Ω(authenticatorTwo.AuthenticateCallCount()).Should(Equal(0))
				})
			})
		})
	})
})
