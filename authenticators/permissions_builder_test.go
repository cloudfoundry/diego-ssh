package authenticators_test

import (
	"encoding/json"
	"net"

	"github.com/cloudfoundry-incubator/diego-ssh/authenticators"
	"github.com/cloudfoundry-incubator/diego-ssh/routes"
	"github.com/cloudfoundry-incubator/diego-ssh/test_helpers/fake_ssh"
	"github.com/cloudfoundry-incubator/receptor"
	"github.com/cloudfoundry-incubator/receptor/fake_receptor"
	"github.com/pivotal-golang/lager/lagertest"
	"golang.org/x/crypto/ssh"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PermissionsBuilder", func() {
	Describe("Build", func() {
		var (
			logger             *lagertest.TestLogger
			expectedRoute      routes.SSHRoute
			desiredLRPResponse receptor.DesiredLRPResponse
			actualLRPResponse  receptor.ActualLRPResponse
			receptorClient     *fake_receptor.FakeClient
			receptorCreds      []byte
			metadata           *fake_ssh.FakeConnMetadata

			permissionsBuilder authenticators.PermissionsBuilder
			permissions        *ssh.Permissions
			buildErr           error
			processGuid        string
			index              int
		)

		BeforeEach(func() {
			logger = lagertest.NewTestLogger("test")

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
				LogGuid: "log-guid",
			}

			actualLRPResponse = receptor.ActualLRPResponse{
				ProcessGuid:  "some-guid",
				Index:        1,
				InstanceGuid: "some-instance-guid",
				Address:      "1.2.3.4",
				Ports: []receptor.PortMapping{
					{ContainerPort: 1111, HostPort: 3333},
				},
			}

			receptorClient = new(fake_receptor.FakeClient)
			receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLRPResponse, nil)
			receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)

			receptorCreds = []byte("receptor-user:receptor-password")
			permissionsBuilder = authenticators.NewPermissionsBuiler(receptorClient)

			remoteAddr, err := net.ResolveIPAddr("ip", "1.1.1.1")
			Expect(err).NotTo(HaveOccurred())
			metadata = &fake_ssh.FakeConnMetadata{}
			metadata.RemoteAddrReturns(remoteAddr)

			processGuid = "some-guid"
			index = 1
		})

		JustBeforeEach(func() {
			permissions, buildErr = permissionsBuilder.Build(processGuid, index, metadata)
		})

		It("gets information about the desired lrp referenced in the username", func() {
			Expect(receptorClient.GetDesiredLRPCallCount()).To(Equal(1))
			Expect(receptorClient.GetDesiredLRPArgsForCall(0)).To(Equal("some-guid"))
		})

		It("gets information about the the actual lrp from the username", func() {
			Expect(receptorClient.ActualLRPByProcessGuidAndIndexCallCount()).To(Equal(1))

			guid, index := receptorClient.ActualLRPByProcessGuidAndIndexArgsForCall(0)
			Expect(guid).To(Equal("some-guid"))
			Expect(index).To(Equal(1))
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

		It("saves log message information in the critical options of the permissions", func() {
			expectedConfig := `{
				"guid": "log-guid",
				"message": "Successful remote access by 1.1.1.1",
				"index": 1
			}`

			Expect(permissions).NotTo(BeNil())
			Expect(permissions.CriticalOptions).NotTo(BeNil())
			Expect(permissions.CriticalOptions["log-message"]).To(MatchJSON(expectedConfig))
		})

		Context("when getting the desired LRP information fails", func() {
			BeforeEach(func() {
				receptorClient.GetDesiredLRPReturns(receptor.DesiredLRPResponse{}, &receptor.Error{})
			})

			It("returns the error", func() {
				Expect(buildErr).To(Equal(&receptor.Error{}))
			})
		})

		Context("when getting the actual LRP information fails", func() {
			BeforeEach(func() {
				receptorClient.ActualLRPByProcessGuidAndIndexReturns(receptor.ActualLRPResponse{}, &receptor.Error{})
			})

			It("returns the error", func() {
				Expect(buildErr).To(Equal(&receptor.Error{}))
			})
		})

		Context("when the container port cannot be found", func() {
			BeforeEach(func() {
				actualLRPResponse.Ports = []receptor.PortMapping{}
				receptorClient.ActualLRPByProcessGuidAndIndexReturns(actualLRPResponse, nil)
			})

			It("returns an empty permission reference", func() {
				Expect(permissions).To(Equal(&ssh.Permissions{}))
			})
		})

		Context("when the desired LRP does not include routes", func() {
			BeforeEach(func() {
				desiredLRPResponse.Routes = nil
				receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
			})

			It("fails the authentication", func() {
				Expect(buildErr).To(Equal(authenticators.RouteNotFoundErr))
			})
		})

		Context("when the desired LRP does not include an SSH route", func() {
			BeforeEach(func() {
				delete(desiredLRPResponse.Routes, routes.DIEGO_SSH)
				receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
			})

			It("fails the authentication", func() {
				Expect(buildErr).To(Equal(authenticators.RouteNotFoundErr))
			})
		})

		Context("when the ssh route fails to unmarshal", func() {
			BeforeEach(func() {
				message := json.RawMessage([]byte(`{,:`))
				desiredLRPResponse.Routes[routes.DIEGO_SSH] = &message
				receptorClient.GetDesiredLRPReturns(desiredLRPResponse, nil)
			})

			It("fails the authentication", func() {
				Expect(buildErr).To(HaveOccurred())
			})
		})
	})
})
