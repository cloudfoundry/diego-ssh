package authenticators_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry-incubator/receptor/fake_receptor"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DiegoProxyAuthenticator", func() {

	var (
		authenticator  *authenticators.DiegoProxyAuthenticator
		metadata       *fake_ssh.FakeConnMetadata
		logger         *lagertest.TestLogger
		receptorClient *fake_receptor.FakeClient
		receptorCreds  []byte

		permissions *ssh.Permissions
		password    []byte
		authErr     error
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		receptorClient = new(fake_receptor.FakeClient)
		receptorCreds = []byte("receptor-user:receptor-password")
		authenticator = authenticators.NewDiegoProxyAuthenticator(logger, receptorClient, receptorCreds)

		metadata = &fake_ssh.FakeConnMetadata{}
		permissions = nil
		password = []byte{}
	})

	JustBeforeEach(func() {
		permissions, authErr = authenticator.Authenticate(metadata, password)
	})

	Context("when a client attempts to authenticate with a user and password", func() {
		Context("when the user name starts with 'diego:'", func() {
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("receptor-user:receptor-password")
			})

			It("authentictes the password against the receptor user:password", func() {
				Ω(authErr).ShouldNot(HaveOccurred())
			})
		})

		Context("when the user name doesn't start with 'diego:'", func() {
			BeforeEach(func() {
				metadata.UserReturns("dora:some-guid")
			})

			It("fails the authentication", func() {
				Ω(authErr).Should(MatchError("Invalid authentication domain"))
			})
		})

		Context("when the password doesn't match the receptor credentials", func() {
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("cf-user:cf-password")
			})

			It("fails the authentication", func() {
				Ω(authErr).Should(MatchError("Invalid credentials"))
			})
		})
	})

	Context("when authentication is successful", func() {
		var lrpResponse receptor.ActualLRPResponse

		BeforeEach(func() {
			metadata.UserReturns("diego:some-guid/0")
			password = []byte("receptor-user:receptor-password")

			lrpResponse = receptor.ActualLRPResponse{
				ProcessGuid:  "some-guid",
				Index:        0,
				InstanceGuid: "some-instance-guid",
				Address:      "1.2.3.4",
				Ports: []receptor.PortMapping{
					{ContainerPort: 2222, HostPort: 3333},
				},
			}

			receptorClient.ActualLRPByProcessGuidAndIndexReturns(lrpResponse, nil)
		})

		It("gets information about the the actual lrp from the username", func() {
			Ω(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).Should(Equal(1))

			guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
			Ω(guid).Should(Equal("some-guid"))
			Ω(index).Should(Equal(0))
		})

		It("saves container information in the critical options of the permissions", func() {
			expectedOptions := map[string]string{
				"diego:process-guid":      "some-guid",
				"diego:index":             "0",
				"diego:instance-guid":     "some-instance-guid",
				"diego:container-address": "1.2.3.4",
				"diego:ssh-daemon-port":   "3333",
			}
			Ω(permissions).ShouldNot(BeNil())
			Ω(permissions.CriticalOptions).Should(Equal(expectedOptions))
		})

		Context("when getting the actual LRP information fails", func() {
			BeforeEach(func() {
				receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
			})

			It("returns the error", func() {
				Ω(authErr).Should(Equal(&receptor.Error{}))
			})
		})
	})
})
