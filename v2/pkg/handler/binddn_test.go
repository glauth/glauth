package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	osuser "os/user"
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

// An address-valued attribute must never yield the address itself as a name
// candidate. That would let a record *named* with an address shadow the record
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
				t.Errorf("bindDNCandidates(%q) produced name candidate %q; an address attribute must resolve by mail only", bindDN, c.name)
			}
		}
	}
}

// nameformat is operator configuration and must not be able to turn an address
// attribute into a name one: with nameformat = "mail", a mail= RDN still
// resolves against mail first.
func TestBindDNCandidatesNameFormatCannotDowngradeMail(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"mail", " ", ""},
	}

	got := bindDNCandidates(backend, "mail=otpuser@glauth.com,ou=superheros,dc=glauth,dc=com")
	if len(got) == 0 || got[0] != (bindDNCandidate{name: "otpuser@glauth.com", byUPN: true}) {
		t.Fatalf("first candidate = %+v, want the address matched by mail", got)
	}
}

// fakeFinder is a Handler of which only FindUser is ever called.
type fakeFinder struct {
	Handler
	find func(name string, byUPN bool) (bool, config.User, error)
}

func (f fakeFinder) FindUser(_ context.Context, name string, byUPN bool) (bool, config.User, error) {
	return f.find(name, byUPN)
}

func wrap(finders ...fakeFinder) HandlerWrapper {
	handlers := make([]Handler, len(finders))
	for i, f := range finders {
		handlers[i] = f
	}
	last := len(finders) - 1
	return HandlerWrapper{Handlers: handlers, Count: &last}
}

func finderFor(users ...config.User) fakeFinder {
	return fakeFinder{find: func(name string, byUPN bool) (bool, config.User, error) {
		for _, u := range users {
			if (!byUPN && u.Name == name) || (byUPN && u.Mail == name) {
				return true, u, nil
			}
		}
		return false, config.User{}, nil
	}}
}

func failingFinder(err error) fakeFinder {
	return fakeFinder{find: func(string, bool) (bool, config.User, error) {
		return false, config.User{}, err
	}}
}

func TestFindLocalRecord(t *testing.T) {
	ctx := context.Background()
	byName := []bindDNCandidate{{name: "alice"}}
	withOTP := config.User{Name: "alice", OTPSecret: "secret"}
	withoutOTP := config.User{Name: "alice"}

	t.Run("a failed lookup is an error, not an absent record", func(t *testing.T) {
		// Waiving the factor on a database outage would switch it off for
		// every user at once.
		_, found, err := findLocalRecord(ctx, wrap(failingFinder(errors.New("connection refused"))), byName)
		if err == nil || found {
			t.Fatalf("found=%v err=%v, want an error", found, err)
		}
	})

	t.Run("a failure after a record without a factor still refuses", func(t *testing.T) {
		// The handler that failed might hold the record that has one.
		_, _, err := findLocalRecord(ctx, wrap(finderFor(withoutOTP), failingFinder(errors.New("timeout"))), byName)
		if err == nil {
			t.Fatal("want an error: a later handler could hold the factor-bearing record")
		}
	})

	for name, notFound := range map[string]error{
		"sql.ErrNoRows":         sql.ErrNoRows,
		"wrapped sql.ErrNoRows": fmt.Errorf("query: %w", sql.ErrNoRows),
		"user.UnknownUserError": osuser.UnknownUserError("alice"),
	} {
		t.Run("a backend reporting no such user as "+name+" keeps the waiver", func(t *testing.T) {
			_, found, err := findLocalRecord(ctx, wrap(failingFinder(notFound)), byName)
			if err != nil || found {
				t.Fatalf("found=%v err=%v, want not found and no error", found, err)
			}
		})
	}

	t.Run("a later handler's factor-bearing record beats an earlier bare one", func(t *testing.T) {
		user, found, err := findLocalRecord(ctx, wrap(finderFor(withoutOTP), finderFor(withOTP)), byName)
		if err != nil || !found || user.OTPSecret == "" {
			t.Fatalf("user=%+v found=%v err=%v, want the record with a factor", user, found, err)
		}
	})

	t.Run("a later candidate's factor-bearing record beats an earlier bare one", func(t *testing.T) {
		bare := config.User{Name: "alice@corp.example"}
		candidates := []bindDNCandidate{{name: "alice@corp.example"}, {name: "alice"}}
		user, found, err := findLocalRecord(ctx, wrap(finderFor(bare, withOTP)), candidates)
		if err != nil || !found || user.Name != "alice" {
			t.Fatalf("user=%+v found=%v err=%v, want alice's factor-bearing record", user, found, err)
		}
	})

	t.Run("a record with no factor is still returned when nothing better exists", func(t *testing.T) {
		user, found, err := findLocalRecord(ctx, wrap(finderFor(withoutOTP)), byName)
		if err != nil || !found || user.OTPSecret != "" {
			t.Fatalf("user=%+v found=%v err=%v", user, found, err)
		}
	})

	t.Run("a disabled candidate wins over an earlier enabled record", func(t *testing.T) {
		// A multi-valued RDN such as cn=enabled+uid=disabled yields both
		// spellings as candidates; the disabled one must win so the Bind guard
		// rejects it instead of binding the disabled account upstream
		// (GHSA-2wj6-h65w-v37c).
		enabled := config.User{Name: "enabled"}
		disabled := config.User{Name: "disabled", Disabled: true}
		candidates := []bindDNCandidate{{name: "enabled"}, {name: "disabled"}}
		user, found, err := findLocalRecord(ctx, wrap(finderFor(enabled, disabled)), candidates)
		if err != nil || !found || !user.Disabled {
			t.Fatalf("user=%+v found=%v err=%v, want the disabled record", user, found, err)
		}
	})

	t.Run("a disabled candidate wins even when a factor-bearing one is found first", func(t *testing.T) {
		// The scan must not stop at the first factor-bearing match: a later
		// disabled spelling still has to win over it.
		disabled := config.User{Name: "disabled", Disabled: true}
		candidates := []bindDNCandidate{{name: "alice"}, {name: "disabled"}}
		user, found, err := findLocalRecord(ctx, wrap(finderFor(withOTP, disabled)), candidates)
		if err != nil || !found || !user.Disabled {
			t.Fatalf("user=%+v found=%v err=%v, want the disabled record to win", user, found, err)
		}
	})

	t.Run("a wrapper with no Count and empty trailing slots does not panic", func(t *testing.T) {
		// The server allocates more slots than it fills, and sets Count; a
		// caller that leaves Count unset must still be safe.
		handlers := HandlerWrapper{Handlers: []Handler{finderFor(withOTP), nil, nil}}
		user, found, err := findLocalRecord(ctx, handlers, byName)
		if err != nil || !found || user.OTPSecret == "" {
			t.Fatalf("user=%+v found=%v err=%v", user, found, err)
		}
		if _, found, err := findLocalRecord(ctx, HandlerWrapper{}, byName); err != nil || found {
			t.Fatalf("zero-value wrapper: found=%v err=%v", found, err)
		}
	})

	t.Run("an empty slot among the active handlers refuses rather than hiding later ones", func(t *testing.T) {
		// A plugin that failed to load leaves a nil handler that still counts
		// as active. Treating it as the end of the list would skip the backend
		// holding the factor-bearing record and waive the factor.
		last := 2
		handlers := HandlerWrapper{Handlers: []Handler{finderFor(), nil, finderFor(withOTP)}, Count: &last}
		if _, found, err := findLocalRecord(ctx, handlers, byName); err == nil {
			t.Fatalf("found=%v err=nil, want an error", found)
		}
	})

	t.Run("without Count a gap is skipped, not treated as the end", func(t *testing.T) {
		handlers := HandlerWrapper{Handlers: []Handler{finderFor(), nil, finderFor(withOTP)}}
		user, found, err := findLocalRecord(ctx, handlers, byName)
		if err != nil || !found || user.OTPSecret == "" {
			t.Fatalf("user=%+v found=%v err=%v, want the record behind the gap", user, found, err)
		}
	})

	t.Run("handlers past Count are never consulted", func(t *testing.T) {
		last := 0
		handlers := HandlerWrapper{Handlers: []Handler{finderFor(), finderFor(withOTP)}, Count: &last}
		if _, found, _ := findLocalRecord(ctx, handlers, byName); found {
			t.Fatal("resolved a record from a handler beyond Count")
		}
	})

	t.Run("no record anywhere is not found", func(t *testing.T) {
		_, found, err := findLocalRecord(ctx, wrap(finderFor(), finderFor()), byName)
		if err != nil || found {
			t.Fatalf("found=%v err=%v, want the waiver case", found, err)
		}
	})
}

// An address is never reduced to its local part. alex@child.example and
// alex@parent.example are different people, and resolving either to a local
// "alex" would let one account's token satisfy the gate for the other. A UPN
// that matches no record's mail needs an explicit mapping, not a guess.
func TestBindDNCandidatesNeverGuessFromAddressLocalPart(t *testing.T) {
	backend := &config.Backend{
		BaseDN:            "dc=glauth,dc=com",
		NameFormatAsArray: []string{"cn", "uid"},
	}

	for _, bindDN := range []string{
		"otpuser@corp.example",
		"userPrincipalName=otpuser@corp.example,ou=superheros,dc=glauth,dc=com",
		"mail=otpuser@corp.example,ou=superheros,dc=glauth,dc=com",
	} {
		for _, c := range bindDNCandidates(backend, bindDN) {
			if c.name == "otpuser" {
				t.Errorf("bindDNCandidates(%q) guessed a user from the address local part", bindDN)
			}
		}
	}
}
