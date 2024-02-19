package monitoring

import (
	"time"

	"github.com/rs/zerolog"
)

type LDAPMonitorWatcher struct {
	syncTicker *time.Ticker

	ldap LDAPServerInterface

	monitor MonitorInterface
	logger  *zerolog.Logger
}

func (m *LDAPMonitorWatcher) sync() {
	for {
		select {
		case tick := <-m.syncTicker.C:
			m.logger.Debug().Time("value", tick).Msg("Tick")
			m.storeMetrics()
		}
	}
}

func (m *LDAPMonitorWatcher) storeMetrics() {
	stats := m.ldap.GetStats()

	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "conns"}, float64(stats.Conns)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}
	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "binds"}, float64(stats.Binds)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}
	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "unbinds"}, float64(stats.Unbinds)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}
	if err := m.monitor.SetLDAPMetric(map[string]string{"type": "searches"}, float64(stats.Searches)); err != nil {
		m.logger.Error().Err(err).Msg("failed to set metric")
	}
}

func NewLDAPMonitorWatcher(ldap LDAPServerInterface, monitor MonitorInterface, logger *zerolog.Logger) *LDAPMonitorWatcher {
	m := new(LDAPMonitorWatcher)

	m.syncTicker = time.NewTicker(15 * time.Second)
	m.ldap = ldap
	m.monitor = monitor
	m.logger = logger

	m.ldap.SetStats(true)

	go m.sync()

	return m
}
