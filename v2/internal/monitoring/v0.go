package monitoring

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// The code below liberally borrows from https://github.com/albertito/prometheus-expvar-exporter
// and is adapted (just a little) for our purpose.

type Collector struct {
	url       string
	names     map[string]string
	helps     map[string]string
	labelName map[string]string
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	return
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	resp, err := http.Get(c.url)
	if err != nil {
		log.Printf("Error scraping %q: %v", c.url, err)
		return
	}

	body, err := io.ReadAll(resp.Body)
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

func NewCollector(url string) *Collector {
	c := new(Collector)
	c.url = url
	c.names = map[string]string{
		"proxy":          "glauth_proxy",
		"proxy_frontend": "glauth_proxy_frontend",
		"proxy_backend":  "glauth_proxy_backend",
	}
	c.helps = map[string]string{
		"proxy":          "General Metrics",
		"proxy_frontend": "Frontend Metrics",
		"proxy_backend":  "Backend Metrics",
	}
	c.labelName = map[string]string{
		"proxy":          "metric",
		"proxy_frontend": "metric",
		"proxy_backend":  "metric",
	}

	prometheus.MustRegister(c)

	return c
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
