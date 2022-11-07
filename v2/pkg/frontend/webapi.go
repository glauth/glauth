package frontend

import (
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/glauth/glauth/v2/pkg/assets"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	register(http.DefaultServeMux, log, cfg.TLS, cfg.Listen)
	if cfg.TLS {
		log.Info().Str("address", cfg.Listen).Msg("Starting HTTPS server")
		err := http.ListenAndServeTLS(cfg.Listen, cfg.Cert, cfg.Key, nil)
		if err != nil {
			log.Error().Err(err).Msg("error starting HTTPS server")
			return
		}
	} else {
		log.Info().Str("address", cfg.Listen).Msg("Starting HTTP server")
		err := http.ListenAndServe(cfg.Listen, nil)
		if err != nil {
			log.Error().Err(err).Msg("error starting HTTP server")
			return
		}
	}
}

func register(mux *http.ServeMux, log zerolog.Logger, tls bool, listen string) {
	fs := http.FileServer(http.FS(assets.Content))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Info().Str("path", r.URL.Path).Msg("Web")
		if r.URL.Path != "/" {
			log.Info().Msg("Web 404")
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
	mux.Handle("/assets/", http.StripPrefix("/assets/", fs))
	var url string
	if tls {
		url = fmt.Sprintf("https://%s/debug/vars", listen)
	} else {
		url = fmt.Sprintf("http://%s/debug/vars", listen)
	}
	c := &collector{
		url: url,
		names: map[string]string{
			"proxy":          "glauth_proxy",
			"proxy_frontend": "glauth_proxy_frontend",
			"proxy_backend":  "glauth_proxy_backend",
		},
		helps: map[string]string{
			"proxy":          "General Metrics",
			"proxy_frontend": "Frontend Metrics",
			"proxy_backend":  "Backend Metrics",
		},
		labelName: map[string]string{
			"proxy":          "metric",
			"proxy_frontend": "metric",
			"proxy_backend":  "metric",
		},
	}
	prometheus.MustRegister(c)
	mux.Handle("/metrics", promhttp.Handler())
}

// The code below liberally borrows from https://github.com/albertito/prometheus-expvar-exporter
// and is adapted (just a little) for our purpose.

type collector struct {
	url       string
	names     map[string]string
	helps     map[string]string
	labelName map[string]string
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	return
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	resp, err := http.Get(c.url)
	if err != nil {
		log.Printf("Error scraping %q: %v", c.url, err)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading body of %q: %v", c.url, err)
		return
	}

	// Replace "\xNN" with "?" because the default parser doesn't handle them
	// well.
	re := regexp.MustCompile(`\\x..`)
	body = re.ReplaceAllFunc(body, func(s []byte) []byte {
		return []byte("?")
	})

	var vs map[string]interface{}
	err = json.Unmarshal(body, &vs)
	if err != nil {
		log.Printf("Error unmarshalling json from %q: %v", c.url, err)
		return
	}

	for k, v := range vs {
		name := strings.ReplaceAll(k, "/", "_")
		if n, ok := c.names[k]; ok {
			name = n
		}

		help := fmt.Sprintf("expvar %q", k)
		if h, ok := c.helps[k]; ok {
			help = h
		}

		lnames := []string{}
		if ln, ok := c.labelName[k]; ok {
			lnames = append(lnames, ln)
		}

		desc := prometheus.NewDesc(name, help, lnames, nil)

		switch v := v.(type) {
		case float64:
			ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, v)
		case bool:
			ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue,
				valToFloat(v))
		case map[string]interface{}:
			// We only support explicitly written label names.
			if len(lnames) != 1 {
				continue
			}
			for lk, lv := range v {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue,
					valToFloat(lv), lk)
			}
		case string:
			// Not supported by Prometheus.
			continue
		case []interface{}:
			// Not supported by Prometheus.
			continue
		default:
			continue
		}
	}
}

func valToFloat(v interface{}) float64 {
	switch v := v.(type) {
	case float64:
		return v
	case bool:
		if v {
			return 1.0
		}
		return 0.0
	case string:
		return 0.0
	}
	log.Printf("unexpected value type: %#v", v)
	return 0.0
}
