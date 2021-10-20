package frontend

import (
	"net/http"

	"github.com/go-logr/logr"

	"github.com/glauth/glauth/v2/pkg/assets"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	register(http.DefaultServeMux, log)
	if cfg.TLS {
		log.V(3).Info("Starting HTTPS server", "address", cfg.Listen)
		err := http.ListenAndServeTLS(cfg.Listen, cfg.Cert, cfg.Key, nil)
		if err != nil {
			log.Error(err, "Error starting HTTPS server")
			return
		}
	} else {
		log.V(3).Info("Starting HTTP server", "address", cfg.Listen)
		err := http.ListenAndServe(cfg.Listen, nil)
		if err != nil {
			log.Error(err, "Error starting HTTP server")
			return
		}
	}
}

func register(mux *http.ServeMux, log logr.Logger) {
	fs := http.FileServer(http.FS(assets.Content))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.V(6).Info("Web", "path", r.URL.Path)
		if r.URL.Path != "/" {
			log.V(6).Info("Web 404")
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
	mux.Handle("/assets/", http.StripPrefix("/assets/", fs))
}
