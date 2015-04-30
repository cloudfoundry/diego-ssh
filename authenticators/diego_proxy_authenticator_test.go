package authenticators_test

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry-incubator/receptor/fake_receptor"
	fake_logs "github.com/cloudfoundry/dropsonde/log_sender/fake"
	"github.com/cloudfoundry/dropsonde/logs"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DiegoProxyAuthenticator", func() {
	var (
		receptorClient     *fake_receptor.FakeClient
		expectedRoute      routes.SSHRoute
		desiredLRPResponse receptor.DesiredLRPResponse
		actualLrpResponse  receptor.ActualLRPResponse
		authenticator      *authenticators.DiegoProxyAuthenticator
		logger             *lagertest.TestLogger
		receptorCreds      []byte
		metadata           *fake_ssh.FakeConnMetadata
		fakeLogSender      *fake_logs.FakeLogSender
	)

	BeforeEach(func() {
		receptorClient = new(fake_receptor.FakeClient)

		expectedRoute = routes.SSHRoute{
			ContainerPort:   1111,
			PrivateKey:      "pem-encoded-key",
			HostFingerprint: "host-fingerprint",
			User:            "user",
			Password:        "password",
		}

		diegoSSHRoutePayload, err := json.Marshal(expectedRoute)
		Expect(err).NotTo(HaveOccurred())

		diegoSSHRouteMessage := json.RawMessage(diegoSSHRoutePayload)

		desiredLRPResponse = receptor.DesiredLRPResponse{
			ProcessGuid: "some-guid",
			Instances:   2,
			Routes: receptor.RoutingInfo{
				routes.DIEGO_SSH: &diegoSSHRouteMessage,
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

		logger = lagertest.NewTestLogger("test")
		receptorCreds = []byte("receptor-user:receptor-password")
		authenticator = authenticators.NewDiegoProxyAuthenticator(logger, receptorClient, receptorCreds)

		metadata = &fake_ssh.FakeConnMetadata{}

		fakeLogSender = fake_logs.NewFakeLogSender()
		logs.Initialize(fakeLogSender)
	})

	Describe("Authenticate", func() {
		var (
			permissions *ssh.Permissions
			password    []byte
			authErr     error
		)

		BeforeEach(func() {
			ipAddr, err := net.ResolveIPAddr("ip", "1.1.1.1")
			Expect(err).NotTo(HaveOccurred())
			metadata.RemoteAddrReturns(ipAddr)

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
					Expect(authErr).NotTo(HaveOccurred())
				})
			})

			Context("when the user name doesn't start with 'diego:'", func() {
				BeforeEach(func() {
					metadata.UserReturns("dora:some-guid")
				})

				It("fails the authentication", func() {
					Expect(authErr).To(MatchError("Invalid authentication domain"))
				})
			})

			Context("when the password doesn't match the receptor credentials", func() {
				BeforeEach(func() {
					metadata.UserReturns("diego:some-guid/0")
					password = []byte("cf-user:cf-password")
				})

				It("fails the authentication", func() {
					Expect(authErr).To(MatchError("Invalid credentials"))
				})
			})
		})

		Context("when authentication is successful", func() {
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("receptor-user:receptor-password")
			})

			It("gets information about the desired lrp referenced in the username", func() {
				Expect(receptorClient.GetDesiredLRPCallCount()).To(Equal(1))
				Expect(receptorClient.GetDesiredLRPArgsForCall(0)).To(Equal("some-guid"))
			})

			It("gets information about the the actual lrp from the username", func() {
				Expect(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).To(Equal(1))

				guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
				Expect(guid).To(Equal("some-guid"))
				Expect(index).To(Equal(0))
			})

			It("saves container information in the critical options of the permissions", func() {
				expectedConfig := `{
					"address": "1.2.3.4:3333",
					"host_fingerprint": "host-fingerprint",
					"private_key": "pem-encoded-key",
					"user": "user",
					"password": "password"
				}`

				Expect(permissions).NotTo(BeNil())
				Expect(permissions.CriticalOptions).NotTo(BeNil())
				Expect(permissions.CriticalOptions["proxy-target-config"]).To(MatchJSON(expectedConfig))
			})

			It("emits a successful log message on behalf of the lrp", func() {
				logMessages := fakeLogSender.GetLogs()
				Expect(logMessages).To(HaveLen(1))
				logMessage := logMessages[0]
				Expect(logMessage.AppId).To(Equal(desiredLRPResponse.LogGuid))
				Expect(logMessage.SourceType).To(Equal("SSH"))
				Expect(logMessage.SourceInstance).To(Equal("0"))
				Expect(logMessage.Message).To(Equal("Successful remote access by 1.1.1.1"))
			})

			Context("when emittimg the log message fails", func() {
				BeforeEach(func() {
					fakeLogSender.ReturnError = errors.New("Boom this blew up")
				})

				It("succeeds to authenticate", func() {
					Expect(authErr).NotTo(HaveOccurred())
				})
			})

			Context("when getting the desired LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.GetDesiredLRPReturns(receptor.DesiredLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Expect(authErr).To(Equal(&receptor.Error{}))
				})
			})

			Context("when getting the actual LRP information fails", func() {
				BeforeEach(func() {
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
				})

				It("returns the error", func() {
					Expect(authErr).To(Equal(&receptor.Error{}))
				})
			})

			Context("when the container port cannot be found", func() {
				BeforeEach(func() {
					actualLrpResponse.Ports = []receptor.PortMapping{}
					receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLrpResponse, nil)
				})

				It("returns an empty permission reference", func() {
					Expect(permissions).To(Equal(&ssh.Permissions{}))
				})
			})
		})

		Context("when the ssh route is misconfigured", func() {
			BeforeEach(func() {
				metadata.UserReturns("diego:some-guid/0")
				password = []byte("receptor-user:receptor-password")
			})

			Context("when the desired LRP does not include routes", func() {
				BeforeEach(func() {
					desiredLRPResponse.Routes = nil
					receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
				})

				It("fails the authentication", func() {
					Expect(authErr).To(Equal(authenticators.RouteNotFoundErr))
				})
			})

			Context("when the desired LRP does not include an SSH route", func() {
				BeforeEach(func() {
					delete(desiredLRPResponse.Routes, routes.DIEGO_SSH)
					receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
				})

				It("fails the authentication", func() {
					Expect(authErr).To(Equal(authenticators.RouteNotFoundErr))
				})
			})

			Context("when the ssh route fails to unmarshal", func() {
				BeforeEach(func() {
					message := json.RawMessage([]byte(`{,:`))
					desiredLRPResponse.Routes[routes.DIEGO_SSH] = &message
					receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
				})

				It("fails the authentication", func() {
					Expect(authErr).To(HaveOccurred())
				})
			})
		})
	})

	Describe("Realm", func() {
		It("is diego", func() {
			Expect(authenticator.Realm()).To(Equal("diego"))
		})
	})
})
