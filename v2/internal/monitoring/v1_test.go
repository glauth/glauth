package monitoring

import (
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"
)

func TestNewMonitorImplementsInterface(t *testing.T) {
	logger := zerolog.Nop()
	m := NewMonitor(&logger)

	i := reflect.TypeOf((*MonitorInterface)(nil)).Elem()

	if !reflect.TypeOf(m).Implements(i) {
		t.Fatal("Monitor doesn't implement MonitorInterface")
	}
}

func TestMonitorSetLDAPMetricSucceeds(t *testing.T) {
	logger := zerolog.Nop()
	m := NewMonitor(&logger)

	labels := map[string]string{"type": "test"}
	m.SetLDAPMetric(labels, float64(10))

	mLDAPMetric := dto.Metric{}
	m.ldapMetric.With(labels).Write(&mLDAPMetric)

	if mLDAPMetric.GetGauge().GetValue() != float64(10) {
		t.Fatalf("metric value should have been set to %v", float64(10))
	}
}

func TestMonitorSetResponseTimeMetricSucceeds(t *testing.T) {
	logger := zerolog.Nop()
	m := NewMonitor(&logger)

	labels := map[string]string{"operation": "test", "status": "0"}
	m.SetResponseTimeMetric(labels, float64(10))

	mResponseTimeMetric := dto.Metric{}
	m.responseTime.With(labels).(prometheus.Metric).Write(&mResponseTimeMetric)

	if mResponseTimeMetric.GetHistogram().GetSampleSum() != float64(10) {
		t.Fatalf("metric value should have been set to %v", float64(10))
	}

	for _, bucket := range mResponseTimeMetric.GetHistogram().GetBucket() {
		if bucket.GetUpperBound() < float64(10) && bucket.GetCumulativeCount() != 0 {
			t.Fatal("there should be no count for this metric bucket")
		}

		if bucket.GetUpperBound() >= float64(10) && bucket.GetCumulativeCount() != 1 {
			t.Fatal("there should be one entry into this metric bucket")
		}

	}
}
