package space_test

import (
	"errors"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/space"
	"github.com/cloudfoundry/cli/plugin/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Space", func() {
	var (
		fakeCliConnection *fakes.FakeCliConnection
		sf                space.SpaceFactory
	)

	BeforeEach(func() {
		fakeCliConnection = &fakes.FakeCliConnection{}
		sf = space.NewSpaceFactory(fakeCliConnection)
	})

	Describe("Get", func() {
		Context("when CC returns a valid response", func() {
			BeforeEach(func() {
				expectedJson := `{
				"metadata": {
					"guid": "space1-guid"
				},
				"entity": {
					"allow_ssh": true
				}
			}`

				fakeCliConnection.CliCommandWithoutTerminalOutputStub = func(args ...string) ([]string, error) {
					if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 1 {
						Expect(args).To(ConsistOf("space", "space1", "--guid"))
						return []string{"space1-guid\n"}, nil
					}
					if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 2 {
						Expect(args).To(ConsistOf("curl", "/v2/spaces/space1-guid"))
						return []string{expectedJson}, nil
					}
					Expect(false).To(BeTrue())
					return []string{}, nil
				}
			})

			It("returns a populated Space model", func() {
				model, err := sf.Get("space1")

				Expect(err).NotTo(HaveOccurred())
				Expect(model.Guid).To(Equal("space1-guid"))
				Expect(model.AllowSSH).To(BeTrue())
			})
		})

		Context("when the space does not exist", func() {
			BeforeEach(func() {
				fakeCliConnection.CliCommandWithoutTerminalOutputReturns(
					[]string{"FAILED", "Space space1 is not found"},
					errors.New("Error executing cli core command"),
				)
			})

			It("returns 'Space not found' error", func() {
				_, err := sf.Get("space1")
				Expect(err).To(MatchError("Space space1 is not found"))

				Expect(fakeCliConnection.CliCommandWithoutTerminalOutputCallCount()).To(Equal(1))
				args := fakeCliConnection.CliCommandWithoutTerminalOutputArgsForCall(0)
				Expect(args).To(ConsistOf("space", "space1", "--guid"))
			})
		})

		Context("when curling the space model fails", func() {
			Context("when CC returns a valid response", func() {
				BeforeEach(func() {
					fakeCliConnection.CliCommandWithoutTerminalOutputStub = func(args ...string) ([]string, error) {
						if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 1 {
							Expect(args).To(ConsistOf("space", "space1", "--guid"))
							return []string{"space1-guid\n"}, nil
						}
						if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 2 {
							Expect(args).To(ConsistOf("curl", "/v2/spaces/space1-guid"))
							return []string{"{}"}, errors.New("Failed to acquire space1 info")
						}
						Expect(false).To(BeTrue())
						return []string{}, nil
					}
				})

				It("returns 'fail to acquire space info' error", func() {
					_, err := sf.Get("space1")

					Expect(err).To(MatchError("Failed to acquire space1 info"))
				})
			})
		})
	})

	Describe("SetBool", func() {
		var aSpace space.Space

		BeforeEach(func() {
			aSpace = space.Space{
				Guid: "myguid",
			}
		})

		It("it sends a cli command", func() {
			sf.SetBool(aSpace, "foobar", true)

			Expect(fakeCliConnection.CliCommandWithoutTerminalOutputCallCount()).To(Equal(1))
			args := fakeCliConnection.CliCommandWithoutTerminalOutputArgsForCall(0)
			Expect(args).To(Equal([]string{"curl", "/v2/spaces/myguid", "-X", "PUT", "-d", `{"foobar":true}`}))
		})

		Context("when the space does not exist", func() {
			BeforeEach(func() {
				fakeCliConnection.CliCommandWithoutTerminalOutputReturns(
					[]string{"FAILED", "Space space1 is not found"},
					errors.New("Error executing cli core command"),
				)
			})

			It("returns 'Space not found' error", func() {
				err := sf.SetBool(aSpace, "foobar", true)
				Expect(err).To(MatchError("Space space1 is not found"))
			})
		})
	})
})
