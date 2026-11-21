package handler

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

type ownCloudTestMonitor struct{}

func (ownCloudTestMonitor) SetResponseTimeMetric(map[string]string, float64) error { return nil }
func (ownCloudTestMonitor) SetLDAPMetric(map[string]string, float64) error         { return nil }

// countingTransport answers every request 200 and records the request targets,
// standing in for an ownCloud front end that would authenticate client
// autodiscovery endpoints such as /status.php without credentials.
type countingTransport struct {
	paths []string
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.paths = append(c.paths, req.URL.Path)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"id":"someone"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// A bind DN whose CN can walk the request off the authenticated provisioning
// endpoint must be refused before any HTTP request is made - otherwise a 200
// from an unauthenticated path such as /status.php is read as a correct
// password (GHSA-gw7r-2pmr-jqmp).
func TestOwnCloudBindRejectsPathInjectionInCN(t *testing.T) {
	logger := zerolog.Nop()
	tracer := noop.NewTracerProvider().Tracer("test")

	_, server := net.Pipe()
	defer server.Close()

	for _, bindDN := range []string{
		"cn=../../../../../status.php,dc=owncloud,dc=com",
		"cn=..,dc=owncloud,dc=com",
		"cn=,dc=owncloud,dc=com",
		"cn=%2e%2e%2fstatus.php,dc=owncloud,dc=com",
		"cn=x?a=b,dc=owncloud,dc=com",
		`cn=x/y,dc=owncloud,dc=com`,
		`cn=x\y,dc=owncloud,dc=com`,
	} {
		transport := &countingTransport{}
		h := ownCloudHandler{
			backend: config.Backend{
				BaseDN:      "dc=owncloud,dc=com",
				Servers:     []string{"https://cloud.example.com/index.php/apps/graphapi/v1.0"},
				UseGraphAPI: true,
			},
			log:      &logger,
			sessions: make(map[string]ownCloudSession),
			lock:     &sync.Mutex{},
			client:   &http.Client{Transport: transport},
			monitor:  ownCloudTestMonitor{},
			tracer:   tracer,
		}

		code, _ := h.Bind(bindDN, "any password at all", server)
		if code != ldap.LDAPResultInvalidCredentials {
			t.Errorf("Bind(%q) = %v, want InvalidCredentials", bindDN, code)
		}
		if len(transport.paths) != 0 {
			t.Errorf("Bind(%q) reached the backend at %v; the CN must be refused before any request", bindDN, transport.paths)
		}
	}
}

// An ordinary CN still reaches the backend, and the escaped name stays a single
// path segment under /users/.
func TestOwnCloudBindOrdinaryCNReachesBackendOnce(t *testing.T) {
	logger := zerolog.Nop()
	tracer := noop.NewTracerProvider().Tracer("test")

	_, server := net.Pipe()
	defer server.Close()

	transport := &countingTransport{}
	h := ownCloudHandler{
		backend: config.Backend{
			BaseDN:      "dc=owncloud,dc=com",
			Servers:     []string{"https://cloud.example.com/index.php/apps/graphapi/v1.0"},
			UseGraphAPI: true,
		},
		log:      &logger,
		sessions: make(map[string]ownCloudSession),
		lock:     &sync.Mutex{},
		client:   &http.Client{Transport: transport},
		monitor:  ownCloudTestMonitor{},
		tracer:   tracer,
	}

	code, _ := h.Bind("cn=alice,dc=owncloud,dc=com", "pw", server)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("Bind(ordinary CN) = %v, want Success", code)
	}
	if len(transport.paths) != 1 {
		t.Fatalf("made %d requests, want 1: %v", len(transport.paths), transport.paths)
	}
	if got := transport.paths[0]; got != "/index.php/apps/graphapi/v1.0/users/alice" {
		t.Errorf("request path = %q, want the user confined under /users/", got)
	}
}

// The search base DN is turned into a /users/<name> request the same way the
// bind DN is, so a crafted base DN must not traverse off that endpoint either
// (the post-bind arm of GHSA-gw7r-2pmr-jqmp). A session is seeded so that, were
// the base DN not rejected, the request would reach the counting transport -
// the assertion of zero requests then means something.
func TestOwnCloudSearchRejectsPathInjectionInBaseDN(t *testing.T) {
	logger := zerolog.Nop()
	tracer := noop.NewTracerProvider().Tracer("test")

	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()

	for _, baseDN := range []string{
		"cn=../../../../../status.php,dc=owncloud,dc=com",
		"cn=%2e%2e%2fstatus.php,dc=owncloud,dc=com",
		`cn=x\y,dc=owncloud,dc=com`,
	} {
		transport := &countingTransport{}
		h := ownCloudHandler{
			backend: config.Backend{
				BaseDN:      "dc=owncloud,dc=com",
				Servers:     []string{"https://cloud.example.com/index.php/apps/graphapi/v1.0"},
				UseGraphAPI: true,
			},
			log:      &logger,
			sessions: make(map[string]ownCloudSession),
			lock:     &sync.Mutex{},
			client:   &http.Client{Transport: transport},
			monitor:  ownCloudTestMonitor{},
			tracer:   tracer,
		}
		// Seed the session this bind would use, pointing at the counting
		// transport, so a non-rejected base DN really would issue a request.
		h.sessions[connID(server)] = ownCloudSession{
			log:         &logger,
			user:        "admin",
			endpoint:    h.backend.Servers[0],
			useGraphAPI: true,
			client:      &http.Client{Transport: transport},
		}

		req := ldap.SearchRequest{
			BaseDN: baseDN,
			Filter: "(objectclass=posixaccount)",
		}
		result, _ := h.Search("cn=admin,dc=owncloud,dc=com", req, server)
		if result.ResultCode != ldap.LDAPResultInsufficientAccessRights {
			t.Errorf("Search(%q) = %v, want InsufficientAccessRights", baseDN, result.ResultCode)
		}
		if len(transport.paths) != 0 {
			t.Errorf("Search(%q) reached the backend at %v; a traversal base DN must be refused first", baseDN, transport.paths)
		}
	}
}
