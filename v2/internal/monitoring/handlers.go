package monitoring

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type API struct {
	logger zerolog.Logger
}

func (a *API) RegisterEndpoints(router *http.ServeMux) {
	router.HandleFunc("/metrics", a.prometheusHTTP)
}

func (a *API) prometheusHTTP(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func NewAPI(logger zerolog.Logger) *API {
	a := new(API)

	a.logger = logger

	return a
}
