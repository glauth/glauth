package handler

import (
	"testing"

	"github.com/glauth/glauth/v2/pkg/config"
)

// A user holding a local record must be resolvable from every spelling of their
// bind DN. Where they are not, the proxy bind path waives the OTP/YubiKey check
// for a user who has one configured - the bypass in GHSA-hx8m-chmx-x2j3.
func TestBindDNCandidatesResolveEverySpelling(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"cn", "uid"},
	}

	for _, tc := range []struct {
		name   string
		bindDN string
		want   bindDNCandidate
	}{
		{
			"first nameformat element",
			"cn=otpuser,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			// Bypassed before the fix: only NameFormatAsArray[0] was stripped,
			// so this resolved to the literal "uid=otpuser" and missed.
			"second nameformat element",
			"uid=otpuser,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			// Bypassed before the fix: the proxy had no UPN branch at all, while
			// the backend resolves this against mail.
			"UPN / e-mail",
			"otpuser@glauth.com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			"UPN is matched case-insensitively",
			"OTPUSER@GLAUTH.COM",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			"no group component",
			"cn=otpuser,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			"RDN value that is itself a UPN",
			"cn=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			// Active Directory accepts this logon form, so the proxy must
			// resolve it too or the factor is waived for an AD-backed user.
			"DOMAIN\\user logon name",
			`glauth\otpuser`,
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			"DOMAIN\\user is case-insensitive",
			`GLAUTH\OTPUSER`,
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			// Attribute names we never configure still have to resolve: an
			// upstream may well accept them.
			"userPrincipalName= RDN",
			"userPrincipalName=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			"sAMAccountName= RDN",
			"sAMAccountName=otpuser,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			"mail= RDN",
			"mail=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			// Splitting on a raw comma would yield "someone\" and miss.
			"RFC 4514 escaped comma in the value",
			`cn=last\, first,ou=superheros,dc=glauth,dc=com`,
			bindDNCandidate{name: "last, first", byUPN: false},
		},
		{
			"RFC 4514 hex escape in the value",
			`cn=last\2c first,ou=superheros,dc=glauth,dc=com`,
			bindDNCandidate{name: "last, first", byUPN: false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bindDNCandidates(backend, tc.bindDN)
			for _, c := range got {
				if c == tc.want {
					return
				}
			}
			t.Errorf("bindDNCandidates(%q) = %+v, missing %+v", tc.bindDN, got, tc.want)
		})
	}
}

// The waiver must still apply to users we genuinely hold no record for, so that
// proxy deployments without local records keep working.
func TestBindDNCandidatesDoNotInventUsers(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"cn", "uid"},
	}

	for _, bindDN := range []string{
		"cn=nobody,ou=superheros,dc=glauth,dc=com",
		"nobody@glauth.com",
	} {
		for _, c := range bindDNCandidates(backend, bindDN) {
			if c.name == "otpuser" || c.name == "otpuser@glauth.com" {
				t.Errorf("bindDNCandidates(%q) produced unrelated identity %q", bindDN, c.name)
			}
		}
	}
}
