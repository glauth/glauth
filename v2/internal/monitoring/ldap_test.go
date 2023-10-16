package monitoring

import (
	"testing"
	"time"

	"github.com/nmcclain/ldap"
	"github.com/rs/zerolog"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -build_flags=--mod=mod -package monitoring -destination ./mock_interfaces.go -source=./interfaces.go

func TestNewLDAPMonitorWatcherRunsOnASchedule(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockMonitor := NewMockMonitorInterface(ctrl)
	mockLDAPServer := NewMockLDAPServerInterface(ctrl)

	stats := ldap.Stats{}

	mockLDAPServer.EXPECT().SetStats(true).Times(1)
	mockLDAPServer.EXPECT().GetStats().MinTimes(1).Return(stats)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "conns"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "binds"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "unbinds"}, float64(0)).MinTimes(1)
	mockMonitor.EXPECT().SetLDAPMetric(map[string]string{"type": "searches"}, float64(0)).MinTimes(1)

	logger := zerolog.Nop()
	m := NewLDAPMonitorWatcher(mockLDAPServer, mockMonitor, &logger)

	m.syncTicker = time.NewTicker(5 * time.Microsecond)

	// allow goroutine to start and ticker to tick
	time.Sleep(10 * time.Millisecond)
}
