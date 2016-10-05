package handlers

import (
	"net/http"

	"code.cloudfoundry.org/lager"
)

func HealthCheck(logger lager.Logger, writer http.ResponseWriter, request *http.Request) {
}
