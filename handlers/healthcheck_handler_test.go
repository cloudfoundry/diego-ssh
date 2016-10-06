package handlers_test

import (
	"net/http"
	"net/http/httptest"

	"code.cloudfoundry.org/diego-ssh/handlers"
	"code.cloudfoundry.org/lager/lagertest"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HealthCheckHandler", func() {
	Context("when sending healthcheck request", func() {

		var (
			handler handlers.HealthCheckHandler
			logger  *lagertest.TestLogger
		)

		BeforeEach(func() {
			logger = lagertest.NewTestLogger("test")
			handler = handlers.NewHealthCheckHandler(logger)
		})

		It("should return a 200 response", func() {
			req, err := http.NewRequest("GET", "/", nil)
			Expect(err).NotTo(HaveOccurred())
			res := httptest.NewRecorder()

			handler.HealthCheck(res, req)

			Expect(res.Code).To(Equal(http.StatusOK))
		})
	})
})
