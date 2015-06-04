package app_test

import (
	"errors"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/app"
	"github.com/cloudfoundry/cli/plugin/fakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("App", func() {
	var (
		fakeCliConnection *fakes.FakeCliConnection
		af                app.AppFactory
	)

	BeforeEach(func() {
		fakeCliConnection = &fakes.FakeCliConnection{}
		af = app.NewAppFactory(fakeCliConnection)
	})

	Describe("Get", func() {
		Context("when CC returns a valid response", func() {
			BeforeEach(func() {
				expectedJson := `{
				"metadata": {
					"guid": "app1-guid"
				},
				"entity": {
					"instances": 1,
					"state": "STARTED",
					"diego": true,
					"enable_ssh": true
				}
			}`

				fakeCliConnection.CliCommandWithoutTerminalOutputStub = func(args ...string) ([]string, error) {
					if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 1 {
						Expect(args).To(ConsistOf("app", "app1", "--guid"))
						return []string{"app1-guid\n"}, nil
					}
					if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 2 {
						Expect(args).To(ConsistOf("curl", "/v2/apps/app1-guid"))
						return []string{expectedJson}, nil
					}
					Expect(false).To(BeTrue())
					return []string{}, nil
				}
			})

			It("returns a populated App model", func() {
				model, err := af.Get("app1")

				Expect(err).NotTo(HaveOccurred())
				Expect(model.Guid).To(Equal("app1-guid"))
				Expect(model.EnableSSH).To(BeTrue())
				Expect(model.Diego).To(BeTrue())
				Expect(model.State).To(Equal("STARTED"))
			})
		})

		Context("when the app does not exist", func() {
			BeforeEach(func() {
				fakeCliConnection.CliCommandWithoutTerminalOutputReturns(
					[]string{"FAILED", "App app1 is not found"},
					errors.New("Error executing cli core command"),
				)
			})

			It("returns 'App not found' error", func() {
				_, err := af.Get("app1")
				Expect(err).To(MatchError("App app1 is not found"))

				Expect(fakeCliConnection.CliCommandWithoutTerminalOutputCallCount()).To(Equal(1))
				args := fakeCliConnection.CliCommandWithoutTerminalOutputArgsForCall(0)
				Expect(args).To(ConsistOf("app", "app1", "--guid"))
			})
		})

		Context("when curling the app model fails", func() {
			Context("when CC returns a valid response", func() {
				BeforeEach(func() {
					fakeCliConnection.CliCommandWithoutTerminalOutputStub = func(args ...string) ([]string, error) {
						if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 1 {
							Expect(args).To(ConsistOf("app", "app1", "--guid"))
							return []string{"app1-guid\n"}, nil
						}
						if fakeCliConnection.CliCommandWithoutTerminalOutputCallCount() == 2 {
							Expect(args).To(ConsistOf("curl", "/v2/apps/app1-guid"))
							return []string{"{}"}, errors.New("Failed to acquire app1 info")
						}
						Expect(false).To(BeTrue())
						return []string{}, nil
					}
				})

				It("returns 'fail to acquire app info' error", func() {
					_, err := af.Get("app1")

					Expect(err).To(MatchError("Failed to acquire app1 info"))
				})
			})
		})
	})
})
