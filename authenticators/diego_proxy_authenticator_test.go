package authenticators_test

import (
	"encoding/json"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/models"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry-incubator/receptor/fake_receptor"
	"github.com/cloudfoundry-incubator/route-emitter/cfroutes"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DiegoProxyAuthenticator", func() {
	var (
		receptorClient     *fake_receptor.FakeClient
		expectedRoute      models.SSHRoute
		desiredLRPResponse receptor.DesiredLRPResponse
		actualLrpResponse  receptor.ActualLRPResponse
	)

	BeforeEach(func() {
		receptorClient = new(fake_receptor.FakeClient)

		cfRoutes, err := json.Marshal(cfroutes.CFRoutes{
			cfroutes.CFRoute{
				Hostnames: []string{"host1.example.com", "host2.example.com"},
				Port:      8080,
			},
		})
		Ω(err).ShouldNot(HaveOccurred())

		expectedRoute = models.SSHRoute{
			ContainerPort:   1111,
			PrivateKey:      "pem-encoded-key",
			HostFingerprint: "host-fingerprint",
			User:            "user",
			Password:        "password",
		}

		diegoSSHRoutePayload, err := json.Marshal(expectedRoute)
		Ω(err).ShouldNot(HaveOccurred())

		cfRoutesMessage := json.RawMessage(cfRoutes)
		diegoSSHRouteMessage := json.RawMessage(diegoSSHRoutePayload)

		desiredLRPResponse = receptor.DesiredLRPResponse{
			ProcessGuid: "some-guid",
			Instances:   2,
			Routes: receptor.RoutingInfo{
				cfroutes.CF_ROUTER: &cfRoutesMessage,
				models.DIEGO_SSH:   &diegoSSHRouteMessage,
			},
		}

		actualLrpResponse = receptor.ActualLRPResponse{
			ProcessGuid:  "some-guid",
			Index:        0,
			InstanceGuid: "some-instance-guid",
			Address:      "1.2.3.4",
			Ports: []receptor.PortMapping{
				{ContainerPort: 1111, HostPort: 3333},
			},
		}

		receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLrpResponse, nil)
		receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
	})

	Describe("Authenticate", func() {
		var (
			authenticator *authenticators.DiegoProxyAuthenticator
			metadata      *fake_ssh.FakeConnMetadata
			logger        *lagertest.TestLogger
			receptorCreds []byte

			permissions *ssh.Permissions
			password    []byte
			authErr     error
		)

		BeforeEach(func() {
			logger = lagertest.NewTestLogger("test")
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

				It("authenticates the password against the receptor user:password", func() {
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
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("receptor-user:receptor-password")
			})

			It("gets information about the desired lrp referenced in the username", func() {
				Ω(receptorClient.GetDesiredLRPCallCount()).Should(Equal(1))
				Ω(receptorClient.GetDesiredLRPArgsForCall(0)).Should(Equal("some-guid"))
			})

			It("gets information about the the actual lrp from the username", func() {
				Ω(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).Should(Equal(1))

				guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
				Ω(guid).Should(Equal("some-guid"))
				Ω(index).Should(Equal(0))
			})

			It("saves container information in the critical options of the permissions", func() {
				expectedConfig := `{
					"address": "1.2.3.4:3333",
					"host_fingerprint": "host-fingerprint",
					"private_key": "pem-encoded-key",
					"user": "user",
					"password": "password"
				}`

				Ω(permissions).ShouldNot(BeNil())
				Ω(permissions.CriticalOptions).ShouldNot(BeNil())
				Ω(permissions.CriticalOptions["proxy-target-config"]).Should(MatchJSON(expectedConfig))
			})

			Context("when getting the desired LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.GetDesiredLRPReturns(receptor.DesiredLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Ω(authErr).Should(Equal(&receptor.Error{}))
				})
			})

			Context("when getting the actual LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Ω(authErr).Should(Equal(&receptor.Error{}))
				})
			})

			Context("when the container port cannot be found", func() {
				BeforeEach(func() {
					actualLrpResponse.Ports = []receptor.PortMapping{}
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLrpResponse, nil)
				})

				It("returns an empty permission reference", func() {
					Ω(permissions).Should(Equal(&ssh.Permissions{}))
				})
			})
		})

		Context("when the ssh route is misconfigured", func() {
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("receptor-user:receptor-password")

				Context("when the desired LRP does not include routes", func() {
					BeforeEach(func() {
						desiredLRPResponse.Routes = nil
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(authErr).Should(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the desired LRP does not include an SSH route", func() {
					BeforeEach(func() {
						delete(desiredLRPResponse.Routes, models.DIEGO_SSH)
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(authErr).Should(Equal(authenticators.RouteNotFoundErr))
					})
				})

				Context("when the ssh route fails to unmarshal", func() {
					BeforeEach(func() {
						message := json.RawMessage([]byte(`{,:`))
						desiredLRPResponse.Routes[models.DIEGO_SSH] = &message
						receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
					})

					It("fails the authentication", func() {
						Ω(authErr).Should(HaveOccurred())
					})
				})
			})
		})
	})
})
