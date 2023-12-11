package monitoring

import "github.com/glauth/ldap"

type MonitorInterface interface {
	SetResponseTimeMetric(map[string]string, float64) error
	SetLDAPMetric(map[string]string, float64) error
}

type LDAPServerInterface interface {
	SetStats(bool)
	GetStats() ldap.Stats
}
