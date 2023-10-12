package monitoring

type MonitorInterface interface {
	SetResponseTimeMetric(map[string]string, float64) error
	SetLDAPMetric(map[string]string, float64) error
}
