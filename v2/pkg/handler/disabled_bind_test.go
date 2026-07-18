package handler

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/crypto/bcrypt"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

type disabledBindTestMonitor struct{}

func (disabledBindTestMonitor) SetResponseTimeMetric(map[string]string, float64) error {
	return nil
}

func (disabledBindTestMonitor) SetLDAPMetric(map[string]string, float64) error {
	return nil
}

func TestConfigBackendDisabledUserCannotBind(t *testing.T) {
	pw := "correct horse"
	raw, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	hexHash := hex.EncodeToString(raw)

	cfg := &config.Config{}
	cfg.Users = []config.User{
		{Name: "activeuser", PrimaryGroup: 5501, PassBcrypt: hexHash, Disabled: false},
		{Name: "disableduser", PrimaryGroup: 5501, PassBcrypt: hexHash, Disabled: true},
	}

	logger := zerolog.Nop()
	tracer := noop.NewTracerProvider().Tracer("f001")
	helper := NewLDAPOpsHelper(tracer)
	h := configHandler{
		backend: config.Backend{
			BaseDN:             "dc=example,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
		},
		log:       &logger,
		cfg:       cfg,
		ldohelper: helper,
		monitor:   disabledBindTestMonitor{},
		tracer:    tracer,
	}
	_, server := net.Pipe()
	defer server.Close()

	bind := func(dn, pass string) ldap.LDAPResultCode {
		code, _ := h.Bind(dn, pass, server)
		return code
	}

	if code := bind("cn=activeuser,dc=example,dc=com", pw); code != ldap.LDAPResultSuccess {
		t.Fatalf("active user with correct pw should bind, got %d", code)
	}
	if code := bind("cn=disableduser,dc=example,dc=com", pw); code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("disabled user must be rejected; got code %d, want InvalidCredentials(49)", code)
	}
}
