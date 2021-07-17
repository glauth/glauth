package frontend

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/glauth/glauth/pkg/assets"
	"github.com/go-logr/logr"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.V(6).Info("Web", "path", r.URL.Path)
		if r.URL.Path != "/" {
			log.V(6).Info("Web 404")
			http.NotFound(w, r)
			return
		}
		pageTemplate, err := assets.Asset("assets/index.html")
		if err != nil {
			log.Error(err, "Error with HTTP server template asset")
			return
		}
		fmt.Fprintf(w, string(pageTemplate))
	})
	http.HandleFunc("/assets/", webStaticHandler(log))
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

// webStaticHandler serves embedded static web files (js&css)
func webStaticHandler(log logr.Logger) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		assetPath := r.URL.Path[1:]
		staticAsset, err := assets.Asset(assetPath)
		if err != nil {
			log.Error(err, "Cannot access asset")
			http.NotFound(w, r)
			return
		}
		headers := w.Header()
		if strings.HasSuffix(assetPath, ".js") {
			headers["Content-Type"] = []string{"application/javascript"}
		} else if strings.HasSuffix(assetPath, ".css") {
			headers["Content-Type"] = []string{"text/css"}
		}
		io.Copy(w, bytes.NewReader(staticAsset))
	}
}
