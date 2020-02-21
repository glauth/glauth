package frontend

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/glauth/glauth/pkg/assets"
	"github.com/glauth/glauth/pkg/config"
	logging "github.com/op/go-logging"
)

// RunAPI provides a basic REST API
func RunAPI(log *logging.Logger, cfg *config.Config) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Debug(fmt.Sprintf("Web: %s", r.URL.Path))
		if r.URL.Path != "/" {
			log.Debug("Web 404")
			http.NotFound(w, r)
			return
		}
		pageTemplate, err := assets.Asset("assets/index.html")
		if err != nil {
			log.Fatal(fmt.Sprintf("Error with HTTP server template asset: %s", err.Error()))
		}
		fmt.Fprintf(w, string(pageTemplate))
	})
	http.HandleFunc("/assets/", webStaticHandler(log))
	if cfg.API.TLS {
		log.Notice(fmt.Sprintf("Starting HTTPS server on %s", cfg.API.Listen))
		err := http.ListenAndServeTLS(cfg.API.Listen, cfg.API.Cert, cfg.API.Key, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error starting HTTPS server: %s", err.Error()))
		}
	} else {
		log.Notice(fmt.Sprintf("Starting HTTP server on %s", cfg.API.Listen))
		err := http.ListenAndServe(cfg.API.Listen, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error starting HTTP server: %s", err.Error()))
		}
	}
}

// webStaticHandler serves embedded static web files (js&css)
func webStaticHandler(log *logging.Logger) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		assetPath := r.URL.Path[1:]
		staticAsset, err := assets.Asset(assetPath)
		if err != nil {
			log.Error(err.Error())
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
