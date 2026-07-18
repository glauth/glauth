package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"

	"github.com/GeertJohan/yubigo"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

type bindTestHandler struct {
	backend config.Backend
	cfg     config.Config
	log     zerolog.Logger
	user    config.User
}

func (h *bindTestHandler) GetBackend() config.Backend { return h.backend }
func (h *bindTestHandler) GetLog() *zerolog.Logger    { return &h.log }
func (h *bindTestHandler) GetCfg() *config.Config     { return &h.cfg }
func (h *bindTestHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

func (h *bindTestHandler) FindUser(_ context.Context, userName string, _ bool) (bool, config.User, error) {
	if userName == h.user.Name {
		return true, h.user, nil
	}
	return false, config.User{}, nil
}

func (h *bindTestHandler) FindGroup(context.Context, string) (bool, config.Group, error) {
	return false, config.Group{}, nil
}

func (h *bindTestHandler) FindPosixAccounts(context.Context, string) ([]*ldap.Entry, error) {
	return nil, nil
}

func (h *bindTestHandler) FindPosixGroups(context.Context, string) ([]*ldap.Entry, error) {
	return nil, nil
}

func sha256Password(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func TestLDAPOpsHelperBindRejectsUnauthenticatedAndPasswordlessBinds(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		user       config.User
		wantResult ldap.LDAPResultCode
	}{
		{
			name:       "named empty password is unauthenticated bind",
			password:   "",
			wantResult: ldap.LDAPResultUnwillingToPerform,
		},
		{
			name:       "arbitrary password without verifier",
			password:   "definitely-wrong",
			wantResult: ldap.LDAPResultInvalidCredentials,
		},
		{
			name: "failed app password does not fall through",
			user: config.User{
				Name:          "nopass",
				PassAppSHA256: []string{sha256Password("expected")},
			},
			password:   "definitely-wrong",
			wantResult: ldap.LDAPResultInvalidCredentials,
		},
		{
			name: "matching primary password succeeds",
			user: config.User{
				Name:       "nopass",
				PassSHA256: sha256Password("correct"),
			},
			password:   "correct",
			wantResult: ldap.LDAPResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.user
			if user.Name == "" {
				user.Name = "nopass"
			}
			h := &bindTestHandler{
				backend: config.Backend{
					BaseDN:             "dc=glauth,dc=com",
					NameFormatAsArray:  []string{"cn"},
					GroupFormatAsArray: []string{"ou"},
				},
				user: user,
				log:  zerolog.Nop(),
			}
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()

			helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
			got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", tt.password, conn)
			if err != nil {
				t.Fatalf("Bind returned error: %v", err)
			}
			if got != tt.wantResult {
				t.Fatalf("Bind result = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestLDAPOpsHelperBindAllowsAnonymousBind(t *testing.T) {
	h := &bindTestHandler{
		backend: config.Backend{BaseDN: "dc=glauth,dc=com"},
		log:     zerolog.Nop(),
	}
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
	got, err := helper.Bind(context.Background(), h, "", "", conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if got != ldap.LDAPResultSuccess {
		t.Fatalf("Bind result = %v, want %v", got, ldap.LDAPResultSuccess)
	}
}
