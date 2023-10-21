package monitoring

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type Monitor struct {
	responseTime *prometheus.HistogramVec
	ldapMetric   *prometheus.GaugeVec

	logger *zerolog.Logger
}

func (m *Monitor) SetResponseTimeMetric(tags map[string]string, value float64) error {
	if m.responseTime == nil {
		return fmt.Errorf("metric not instantiated")
	}

	m.responseTime.With(tags).Observe(value)

	return nil
}

func (m *Monitor) SetLDAPMetric(tags map[string]string, value float64) error {
	if m.ldapMetric == nil {
		return fmt.Errorf("metric not instantiated")
	}

	m.ldapMetric.With(tags).Set(value)

	return nil
}

func (m *Monitor) constLabels() map[string]string {
	return map[string]string{
		"library": "github.com/glauth/glauth",
	}

}

func (m *Monitor) registerHistograms() {
	histograms := make([]*prometheus.HistogramVec, 0)

	m.responseTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:        "tcp_response_time_seconds",
			Help:        "tcp_response_time_seconds",
			ConstLabels: m.constLabels(),
		},
		[]string{"operation", "status"},
	)

	histograms = append(histograms, m.responseTime)

	for _, histogram := range histograms {
		err := prometheus.Register(histogram)

		switch err.(type) {
		case nil:
			return
		case prometheus.AlreadyRegisteredError:
			m.logger.Debug().Interface("metric", histogram).Msg("metric already registered")
		default:
			m.logger.Error().Interface("metric", histogram).Msg("metric could not be registered")
		}
	}
}

func (m *Monitor) registerGauges() {
	gauges := make([]*prometheus.GaugeVec, 0)

	m.ldapMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:        "ldap_metric",
			Help:        "ldap_metric",
			ConstLabels: m.constLabels(),
		},
		[]string{"type"},
	)

	gauges = append(gauges, m.ldapMetric)

	for _, gauge := range gauges {
		err := prometheus.Register(gauge)

		switch err.(type) {
		case nil:
			return
		case prometheus.AlreadyRegisteredError:
			m.logger.Debug().Interface("metric", gauge).Msg("metric already registered")
		default:
			m.logger.Error().Interface("metric", gauge).Msg("metric could not be registered")
		}
	}
}

func NewMonitor(logger *zerolog.Logger) *Monitor {
	m := new(Monitor)

	m.logger = logger

	m.registerHistograms()
	m.registerGauges()

	return m
}
