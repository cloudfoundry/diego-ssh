package handlers_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Signals", func() {

	Describe("Signal Mapping", func() {
		It("should have the same length map", func() {
			Expect(handlers.SyscallSignals).To(HaveLen(len(handlers.SSHSignals)))
		})

		It("has the correct mapping", func() {
			for k, v := range handlers.SyscallSignals {
				Expect(k).To(Equal(handlers.SSHSignals[v]))
			}

			for k, v := range handlers.SSHSignals {
				Expect(k).To(Equal(handlers.SyscallSignals[v]))
			}
		})
	})

})
