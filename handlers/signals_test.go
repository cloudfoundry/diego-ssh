package handlers_test

import (
	"github.com/cloudfoundry-incubator/diego-ssh/handlers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Signals", func() {

	Describe("Signal Mapping", func() {
		It("should have the same length map", func() {
			Ω(handlers.SyscallSignals).Should(HaveLen(len(handlers.SSHSignals)))
		})

		It("has the correct mapping", func() {
			for k, v := range handlers.SyscallSignals {
				Ω(k).Should(Equal(handlers.SSHSignals[v]))
			}

			for k, v := range handlers.SSHSignals {
				Ω(k).Should(Equal(handlers.SyscallSignals[v]))
			}
		})
	})

})
