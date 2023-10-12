package assets

import (
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type API struct {
	fileServer http.Handler

	logger zerolog.Logger
}

func (a *API) RegisterEndpoints(router *http.ServeMux) {
	router.HandleFunc("/", a.assets)
	router.Handle("/assets/", http.StripPrefix("/assets/", a.fileServer))
}

func (a *API) assets(w http.ResponseWriter, r *http.Request) {
	a.logger.Info().Str("path", r.URL.Path).Msg("Web")

	if r.URL.Path != "/" {
		log.Info().Msg("Web 404")
		http.NotFound(w, r)
		return
	}

	a.fileServer.ServeHTTP(w, r)
}

func NewAPI(logger zerolog.Logger) *API {
	a := new(API)

	a.logger = logger
	a.fileServer = http.FileServer(http.FS(Content))
	return a
}
