package handlers

import (
	"net/http"

	"code.cloudfoundry.org/lager"
)

type HealthCheckHandler struct {
	logger lager.Logger
}

func NewHealthCheckHandler(logger lager.Logger) HealthCheckHandler {
	logger = logger.Session("healthcheck")
	return HealthCheckHandler{
		logger: logger,
	}
}

func (h *HealthCheckHandler) HealthCheck(writer http.ResponseWriter, request *http.Request) {
	h.logger.Debug("started")
	defer h.logger.Debug("finished")
	writer.WriteHeader(http.StatusOK)
}
