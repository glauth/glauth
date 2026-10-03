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
		{
			// A multi-valued RDN joins AVAs with "+"; each has to be read or a
			// DN spelled this way resolves to nobody and the factor is waived.
			"multi-valued RDN",
			"cn=otpuser+uid=otpuser,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			"multi-valued RDN carrying a mail AVA",
			"cn=otpuser+mail=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: true},
		},
		{
			// RFC 4514 writes a value as a "#"-prefixed BER hexstring;
			// 0c05 is a 5-byte UTF8String.
			"BER hexstring value, UTF8String",
			"cn=#0c076f747075736572,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			"BER hexstring value, PrintableString",
			"cn=#13076f747075736572,ou=superheros,dc=glauth,dc=com",
			bindDNCandidate{name: "otpuser", byUPN: false},
		},
		{
			// A bare UPN must also be tried against the name, for a record
			// whose name is itself the address.
			"bare UPN is matched against name as well as mail",
			"otpuser@glauth.com",
			bindDNCandidate{name: "otpuser@glauth.com", byUPN: false},
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

// A value carried by an attribute that does not name users must never become a
// candidate. Otherwise one user's bind DN resolves a different user's local
// record, and so a different user's second factor - either waiving the real
// user's factor, or demanding someone else's. This was a regression introduced
// while widening the candidate list, caught in review.
func TestBindDNCandidatesIgnoreNonIdentityAttributes(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"cn", "uid"},
	}

	for _, bindDN := range []string{
		"employeeNumber=otpuser,ou=superheros,dc=glauth,dc=com",
		"description=otpuser,ou=superheros,dc=glauth,dc=com",
		"title=otpuser,ou=superheros,dc=glauth,dc=com",
		"o=otpuser,ou=superheros,dc=glauth,dc=com",
	} {
		for _, c := range bindDNCandidates(backend, bindDN) {
			if c.name == "otpuser" {
				t.Errorf("bindDNCandidates(%q) treated a non-identity attribute as a username", bindDN)
			}
		}
	}
}

// An address-valued attribute resolves against mail only. Matching it against
// name as well would let a record *named* with an address shadow the record
// whose mail actually matches.
func TestBindDNCandidatesDoNotShadowMailWithName(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"cn", "uid"},
	}

	for _, bindDN := range []string{
		"mail=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
		"userPrincipalName=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com",
	} {
		for _, c := range bindDNCandidates(backend, bindDN) {
			if !c.byUPN {
				t.Errorf("bindDNCandidates(%q) produced name candidate %q; an address attribute must resolve by mail only",
					bindDN, c.name)
			}
		}
	}
}
