package plugins

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

func entryAttribute(entry *ldap.Entry, name string) ([]string, bool) {
	for _, attr := range entry.Attributes {
		if attr.Name == name {
			return attr.Values, true
		}
	}
	return nil, false
}

// A backend's sshkeyattr setting names the attribute SSH keys are published
// under. The config backend reads it; the SQL backends have to agree, or the
// setting silently does nothing wherever users live in a database.
func TestGetAccountUsesConfiguredSSHKeyAttr(t *testing.T) {
	keys := []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample user@host"}

	h := databaseHandler{
		backend: config.Backend{
			BaseDN:             "dc=glauth,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
			SSHKeyAttr:         "ipaSshPubKey",
		},
		tracer: noop.NewTracerProvider().Tracer("basesqlhandler-test"),
	}

	entry := h.getAccount(context.Background(), "", config.User{Name: "johndoe", SSHKeys: keys})

	if _, found := entryAttribute(entry, "sshPublicKey"); found {
		t.Errorf("account carries sshPublicKey although sshkeyattr is %q", h.backend.SSHKeyAttr)
	}

	got, found := entryAttribute(entry, h.backend.SSHKeyAttr)
	if !found {
		t.Fatalf("account is missing the configured attribute %q", h.backend.SSHKeyAttr)
	}
	if len(got) != len(keys) || got[0] != keys[0] {
		t.Errorf("%s = %v, want %v", h.backend.SSHKeyAttr, got, keys)
	}
}
