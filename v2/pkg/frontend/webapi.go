package frontend

import (
	"fmt"
	"net/http"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/assets"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	router := http.DefaultServeMux

	assets.NewAPI(log).RegisterEndpoints(router)
	monitoring.NewAPI(log).RegisterEndpoints(router)

	if cfg.TLS {
		log.Info().Str("address", cfg.Listen).Msg("Starting HTTPS server")

		monitoring.NewCollector(fmt.Sprintf("https://%s/debug/vars", cfg.Listen))
		if err := http.ListenAndServeTLS(cfg.Listen, cfg.Cert, cfg.Key, nil); err != nil {
			log.Error().Err(err).Msg("error starting HTTPS server")
		}

		return
	}

	log.Info().Str("address", cfg.Listen).Msg("Starting HTTP server")
	monitoring.NewCollector(fmt.Sprintf("http://%s/debug/vars", cfg.Listen))

	if err := http.ListenAndServe(cfg.Listen, nil); err != nil {
		log.Error().Err(err).Msg("error starting HTTP server")
	}

}
