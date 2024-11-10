package handler

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/glauth/ldap"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)
var emailmatcher = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

type LDAPOpsHandler interface {
	GetBackend() config.Backend
	GetLog() *zerolog.Logger
	GetCfg() *config.Config
	GetYubikeyAuth() *yubigo.YubiAuth

	FindUser(ctx context.Context, userName string, searchByUPN bool) (f bool, u config.User, err error)
	FindGroup(ctx context.Context, groupName string) (f bool, g config.Group, err error)
	FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error)
	FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error)
}

type failedBind struct {
	ts time.Time
}

type sourceInfo struct {
	lastSeen  time.Time
	failures  chan failedBind
	waitUntil time.Time
}

type LDAPOpsHelper struct {
	sources     map[string]*sourceInfo
	nextPruning time.Time

	tracer trace.Tracer
}

func NewLDAPOpsHelper(tracer trace.Tracer) LDAPOpsHelper {
	helper := LDAPOpsHelper{
		sources:     make(map[string]*sourceInfo),
		nextPruning: time.Now(),
		tracer:      tracer,
	}
	return helper
}

func (l LDAPOpsHelper) Bind(ctx context.Context, h LDAPOpsHandler, bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.Bind")
	defer span.End()

	if l.isInTimeout(ctx, h, conn) {
		return ldap.LDAPResultUnwillingToPerform, nil
	}

	bindDN = strings.ToLower(bindDN)

	h.GetLog().Info().Str("binddn", bindDN).Str("basedn", h.GetBackend().BaseDN).Str("src", conn.RemoteAddr().String()).Msg("Bind request")

	stats.Frontend.Add("bind_reqs", 1)

	// Special Case: bind as anonymous
	if bindDN == "" && bindSimplePw == "" {
		stats.Frontend.Add("bind_successes", 1)
		h.GetLog().Info().Str("src", conn.RemoteAddr().String()).Msg("Anonymous Bind success")
		return ldap.LDAPResultSuccess, nil
	}

	user, ldapcode := l.findUser(ctx, h, bindDN, true /* checkGroup */)
	if ldapcode != ldap.LDAPResultSuccess {
		return ldapcode, nil
	}

	validotp := false

	if len(user.Yubikey) == 0 && len(user.OTPSecret) == 0 {
		validotp = true
	}

	if len(user.Yubikey) > 0 && h.GetYubikeyAuth() != nil {
		if len(bindSimplePw) > 44 {
			otp := bindSimplePw[len(bindSimplePw)-44:]
			yubikeyid := otp[0:12]
			bindSimplePw = bindSimplePw[:len(bindSimplePw)-44]

			if user.Yubikey == yubikeyid {
				_, ok, _ := h.GetYubikeyAuth().Verify(otp)

				if ok {
					validotp = true
				}
			}
		}
	}

	// Store the full bind password provided before possibly modifying
	// in the otp check
	untouchedBindSimplePw := bindSimplePw

	// Test OTP if is exists
	if len(user.OTPSecret) > 0 && !validotp {
		if len(bindSimplePw) > 6 {
			otp := bindSimplePw[len(bindSimplePw)-6:]
			bindSimplePw = bindSimplePw[:len(bindSimplePw)-6]

			validotp = totp.Validate(otp, user.OTPSecret)
		}
	}

	// finally, validate user's pw

	// check app passwords first
	if user.PassAppBcrypt != nil {
		for index, appPw := range user.PassAppBcrypt {
			decoded, err := hex.DecodeString(appPw)
			if err != nil {
				h.GetLog().Info().Str("incorrect stored hash", "(omitted)").Msg("invalid app credentials")
			} else {
				if bcrypt.CompareHashAndPassword(decoded, []byte(untouchedBindSimplePw)) == nil {
					stats.Frontend.Add("bind_successes", 1)
					h.GetLog().Info().Int("index", index).Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind success using app pw")
					return ldap.LDAPResultSuccess, nil
				}
			}
		}
	}
	if user.PassAppSHA256 != nil {
		hashFull := sha256.New()
		hashFull.Write([]byte(untouchedBindSimplePw))
		for index, appPw := range user.PassAppSHA256 {
			if appPw != hex.EncodeToString(hashFull.Sum(nil)) {
				h.GetLog().Info().Int("index", index).Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Attempt to bind app pw failed")
			} else {
				stats.Frontend.Add("bind_successes", 1)
				h.GetLog().Info().Int("index", index).Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind success using app pw")
				return ldap.LDAPResultSuccess, nil
			}
		}
	}
	if user.PassAppCustom != nil {
		err := user.PassAppCustom(user, untouchedBindSimplePw)
		if err != nil {
			h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Str("error", err.Error()).Msg("Attempt to bind app custom auth failed")
			return ldap.LDAPResultInvalidCredentials, nil
		}

		stats.Frontend.Add("bind_successes", 1)
		h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind success using app custom auth")
		return ldap.LDAPResultSuccess, nil
	}

	// Then ensure the OTP is valid before checking
	if !validotp {
		h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("invalid OTP token")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Now, check the pasword hash
	if user.PassBcrypt != "" {
		decoded, err := hex.DecodeString(user.PassBcrypt)
		if err != nil {
			h.GetLog().Info().Str("incorrect stored hash", "(omitted)").Msg("invalid credentials")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		if bcrypt.CompareHashAndPassword(decoded, []byte(bindSimplePw)) != nil {
			h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("invalid credentials")
			l.maybePutInTimeout(ctx, h, conn, true)
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}
	if user.PassSHA256 != "" {
		hash := sha256.New()
		hash.Write([]byte(bindSimplePw))
		if user.PassSHA256 != hex.EncodeToString(hash.Sum(nil)) {
			h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("invalid credentials")
			l.maybePutInTimeout(ctx, h, conn, true)
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	stats.Frontend.Add("bind_successes", 1)
	h.GetLog().Info().Str("binddn", bindDN).Str("src", conn.RemoteAddr().String()).Msg("Bind success")
	return ldap.LDAPResultSuccess, nil
}

/*
 * TODO #1:
 * Is it possible to map, on-the-fly, ou= -> cn= to maintain backware compatibility? Could be a switch...
 * Or maybe sinmply configure in the .cfg file using the nameformat and groupformat settings?
 * In 3.0 we could change default from cn to ou
 * TODO #2: DONE
 * Returns values when scope==base or scope==sub on a group entry
 * TODO #3: DONE
 * Make sure that when scope==sub, we do not always return, but augment results instead
 * TODO #4: DONE
 * Handle groups as two distinct objectclasses like OLDAP does
 * Q: Does OLDAP return the groups twice when querying root+sub?
 * TODO #5:
 * Document roll out of schemas
 */
func (l LDAPOpsHelper) Search(ctx context.Context, h LDAPOpsHandler, bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.Search")
	defer span.End()

	if l.isInTimeout(ctx, h, conn) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultUnwillingToPerform}, fmt.Errorf("Source is in a timeout")
	}

	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower(h.GetBackend().BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)

	anonymous := len(bindDN) < 1

	var boundUser *config.User
	var ldapcode ldap.LDAPResultCode

	if !anonymous {
		if bindDN, boundUser, ldapcode = l.searchCheckBindDN(ctx, h, baseDN, bindDN, anonymous); ldapcode != ldap.LDAPResultSuccess {
			return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Search Error: Potential bypass of BindDN %s", bindDN)
		}
	}

	h.GetLog().Info().Str("binddn", bindDN).Str("basedn", baseDN).Str("searchbasedn", searchBaseDN).Str("src", conn.RemoteAddr().String()).Int("scope", searchReq.Scope).Str("filter", searchReq.Filter).Msg("Search request")
	stats.Frontend.Add("search_reqs", 1)

	switch entries, ldapcode := l.searchMaybeRootDSEQuery(ctx, h, baseDN, searchBaseDN, searchReq, anonymous); ldapcode {
	case ldap.LDAPResultUnwillingToPerform:
		return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Search Error: No BaseDN provided")
	case ldap.LDAPResultInsufficientAccessRights:
		return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Root DSE Search Error: Anonymous BindDN not allowed %s", bindDN)
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	// Past this point, there is no reason to allow anonymous searches
	if anonymous {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: Anonymous BindDN not allowed %s", bindDN)
	}

	switch entries, ldapcode, attributename := l.searchMaybeSchemaQuery(ctx, h, baseDN, searchBaseDN, searchReq, anonymous); ldapcode {
	case ldap.LDAPResultOperationsError:
		return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Schema Error: attribute %s cannot be read", *attributename)
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	// Past this further point, we are looking at tree searches... not all standard searches yet, though

	// But first, let's only allow legal searches
	if !strings.HasSuffix(bindDN, fmt.Sprintf(",%s", baseDN)) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: BindDN %s not in our BaseDN %s", bindDN, h.GetBackend().BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.GetBackend().BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.GetBackend().BaseDN)
	}
	// Unless globally ignored, we will check that a user has capabilities allowing them to perform a search in the requested BaseDN
	if !h.GetCfg().Behaviors.IgnoreCapabilities && !l.checkCapability(ctx, *boundUser, "search", []string{"*", searchBaseDN}) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: no capability allowing BindDN %s to perform search in %s", bindDN, searchBaseDN)
	}

	switch entries, ldapcode := l.searchMaybeTopLevelNodes(ctx, h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybeTopLevelGroupsNode(ctx, h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybeTopLevelUsersNode(ctx, h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}

	switch entries, ldapcode := l.searchMaybePosixGroups(ctx, h, baseDN, searchBaseDN, searchReq, filterEntity); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybePosixAccounts(ctx, h, baseDN, searchBaseDN, searchReq, filterEntity); ldapcode {
	case ldap.LDAPResultSuccess:
		stats.Frontend.Add("search_successes", 1)
		h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Search OK")
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	// So, this should be an ERROR condition! Right..?
	entries := []*ldap.Entry{}
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Returns: LDAPResultSuccess or any ldap code returned by findUser
func (l LDAPOpsHelper) searchCheckBindDN(ctx context.Context, h LDAPOpsHandler, baseDN string, bindDN string, anonymous bool) (newBindDN string, boundUser *config.User, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchCheckBindDN")
	defer span.End()

	boundUser, ldapcode := l.findUser(ctx, h, bindDN, false /* checkGroup */)
	if ldapcode != ldap.LDAPResultSuccess {
		return "", nil, ldapcode
	}
	// What if this user was bound using their UPN? We still want to enforce baseDN etc so we
	// have to rewire them to their original DN which is of course a waste of cycles.
	// TODO Down the road we would want to perform lightweight memoization of DNs to UPNs
	if emailmatcher.MatchString(bindDN) {
		// cn=serviceuser,ou=svcaccts,dc=glauth,dc=com
		bindDN = fmt.Sprintf("cn=%s,%s", boundUser.Name, baseDN)
	}
	return bindDN, boundUser, ldap.LDAPResultSuccess
}

// Search RootDSE and return information on the server
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultUnwillingToPerform, LDAPResultInsufficientAccessRights
func (l LDAPOpsHelper) searchMaybeRootDSEQuery(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, anonymous bool) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybeRootDSEQuery")
	defer span.End()

	if searchBaseDN != "" {
		return nil, ldap.LDAPResultOther // OK
	}
	/// Only base scope searches allowed if no basedn is provided
	if searchReq.Scope != ldap.ScopeBaseObject {
		h.GetLog().Info().Interface("src", searchReq.Controls).Msg("Search Error: No BaseDN provided")
		return nil, ldap.LDAPResultUnwillingToPerform // KO
	}
	if anonymous && !h.GetBackend().AnonymousDSE {
		return nil, ldap.LDAPResultInsufficientAccessRights // KO
	}

	h.GetLog().Info().Str("special case", "root DSE").Msg("Search request")
	entries := []*ldap.Entry{}
	attrs := []*ldap.EntryAttribute{}
	// unfortunately, objectClass is not to be included so we will respect that
	// attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"*"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "supportedSASLMechanisms", Values: []string{}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "supportedLDAPVersion", Values: []string{"3"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "supportedControl", Values: []string{}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "supportedCapabilities", Values: []string{}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "subschemaSubentry", Values: []string{"cn=schema"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "serverName", Values: []string{"unknown"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "namingContexts", Values: []string{baseDN}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "defaultNamingContext", Values: []string{baseDN}})
	attrs = l.collectRequestedAttributesBack(ctx, attrs, searchReq)
	entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Root Search OK")
	return entries, ldap.LDAPResultSuccess
}

// Search and return the information, after indirection from the RootDSE
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
func (l LDAPOpsHelper) searchMaybeSchemaQuery(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, anonymous bool) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode, attributename *string) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybeSchemaQuery")
	defer span.End()

	if searchBaseDN != "cn=schema" {
		return nil, ldap.LDAPResultOther, nil // OK
	}

	h.GetLog().Info().Str("special case", "schema discovery").Msg("Search request")
	entries := []*ldap.Entry{}
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{"schema"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "hasSubordinates", Values: []string{"false"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "modifiersName", Values: []string{"cn=Directory Manager"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "modifyTimeStamp", Values: []string{"Mar 8, 2021, 12:46:29 PM PST (20210308204629Z)"}})
	// Iterate through schema attributes provided in schema/ directory
	filenames, _ := os.ReadDir("schema")
	for _, filename := range filenames {
		attributename := new(string)
		*attributename = filename.Name()
		file, err := os.Open(filepath.Join("schema", *attributename))
		if err != nil {
			return nil, ldap.LDAPResultOperationsError, attributename
		}
		defer file.Close()
		values := []string{}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			values = append(values, line)
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: filename.Name(), Values: values})
	}
	attrs = l.collectRequestedAttributesBack(ctx, attrs, searchReq)
	entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Schema Discovery OK")
	return entries, ldap.LDAPResultSuccess, nil
}

// Retrieve the top-levell nodes, i.e. the baseDN, groups, members...
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelNodes(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybeTopLevelNodes")
	defer span.End()

	if baseDN != searchBaseDN {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().Info().Str("special case", "top-level browse").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelRootNode(ctx, searchBaseDN))
	}
	entries = append(entries, l.topLevelGroupsNode(ctx, searchBaseDN, "groups"))
	entries = append(entries, l.topLevelUsersNode(ctx, searchBaseDN))
	if searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(ctx, "ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)

		userentries, err := h.FindPosixAccounts(ctx, "ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Browse OK")
	return entries, ldap.LDAPResultSuccess
}

// Search starting from and including the ou=groups node
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelGroupsNode(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybeTopLevelGroupsNode")
	defer span.End()

	if searchBaseDN != fmt.Sprintf("ou=groups,%s", baseDN) {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().Info().Str("special case", "top-level groups node").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelGroupsNode(ctx, searchBaseDN, "groups"))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(ctx, "ou=groups")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Groups Browse OK")
	return entries, ldap.LDAPResultSuccess
}

// Search starting from and including the ou=users node
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelUsersNode(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybeTopLevelUsersNode")
	defer span.End()

	if searchBaseDN != fmt.Sprintf("ou=users,%s", baseDN) {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().Info().Str("special case", "top-level users node").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelUsersNode(ctx, searchBaseDN))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(ctx, "ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)
	}
	if searchReq.Scope == ldap.ScopeWholeSubtree {
		userentries, err := h.FindPosixAccounts(ctx, "ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Top-Level Users Browse OK")
	return entries, ldap.LDAPResultSuccess
}

// Look up posixgroup entries, either through objectlass or parent is ou=groups or ou=users
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
func (l LDAPOpsHelper) searchMaybePosixGroups(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, filterEntity string) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybePosixGroups")
	defer span.End()

	hierarchy := "ou=groups"
	if filterEntity != "posixgroup" {
		bits := strings.Split(strings.Replace(searchBaseDN, baseDN, "", 1), ",")
		if len(bits) != 3 || (bits[1] != "ou=groups" && bits[1] != "ou=users") {
			return nil, ldap.LDAPResultOther // OK
		}
		hierarchy = bits[1]
	}
	h.GetLog().Info().Str("special case", "posix groups").Msg("Search request")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(ctx, hierarchy)
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, l.preFilterEntries(ctx, searchBaseDN, groupentries)...)
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		if hierarchy == "ou=users" {
			userentries, err := h.FindPosixAccounts(ctx, "ou=users")
			if err != nil {
				return nil, ldap.LDAPResultOperationsError
			}
			entries = append(entries, l.preFilterEntries(ctx, searchBaseDN, userentries)...)
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Posix Groups Search OK")
	return entries, ldap.LDAPResultSuccess
}

// Lookup posixaccount entries
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
// This function ignores scopes... for now
func (l LDAPOpsHelper) searchMaybePosixAccounts(ctx context.Context, h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, filterEntity string) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.searchMaybePosixAccounts")
	defer span.End()

	switch filterEntity {
	case "posixaccount", "shadowaccount", "":
		h.GetLog().Info().Str("default case", filterEntity).Msg("Search request")
	default:
		return nil, ldap.LDAPResultOther // OK
	}

	// FixUp: we may be in the process of browsing users from a group ou
	hierarchyString := ""
	if strings.HasSuffix(searchBaseDN, fmt.Sprintf("ou=users,%s", baseDN)) {
		hierarchyString = "ou=users"
	}

	unscopedEntries, err := h.FindPosixAccounts(ctx, hierarchyString)
	if err != nil {
		return nil, ldap.LDAPResultOperationsError
	}

	// Filter out entries, that are not in the search base dn
	entries := []*ldap.Entry{}
	for _, e := range unscopedEntries {
		if strings.HasSuffix(e.DN, searchBaseDN) {
			entries = append(entries, e)
		}
	}

	stats.Frontend.Add("search_successes", 1)
	h.GetLog().Info().Str("filter", searchReq.Filter).Msg("AP: Account Search OK")
	return entries, ldap.LDAPResultSuccess
}

func (l LDAPOpsHelper) topLevelRootNode(ctx context.Context, searchBaseDN string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	dnBits := strings.Split(searchBaseDN, ",")
	for _, dnBit := range dnBits {
		chunk := strings.Split(dnBit, "=")
		attrs = append(attrs, &ldap.EntryAttribute{Name: chunk[0], Values: []string{chunk[1]}})
	}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "dcObject", "top"}})
	return &ldap.Entry{DN: searchBaseDN, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelGroupsNode(ctx context.Context, searchBaseDN string, hierarchy string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"groups"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
	hierarchyStringPrefix := fmt.Sprintf("ou=%s,", hierarchy)
	dn := searchBaseDN
	if !strings.HasPrefix(dn, hierarchyStringPrefix) {
		dn = fmt.Sprintf("%s%s", hierarchyStringPrefix, dn)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelUsersNode(ctx context.Context, searchBaseDN string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{"users"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "top"}})
	dn := searchBaseDN
	if !strings.HasPrefix(dn, "ou=users,") {
		dn = fmt.Sprintf("ou=users,%s", dn)
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

// I am not quite sure why but I found out that, maybe due to my playing around with their DN,
// querying groups and users under a certain node (e.g. ou=users) with a scope of "sub"
// (and only in this scenario!) will defeat the LDAP library's filtering capabilities.
// Some day, hopefully, I'll fix this directly in the library.
func (l LDAPOpsHelper) preFilterEntries(ctx context.Context, searchBaseDN string, entries []*ldap.Entry) (resultentries []*ldap.Entry) {
	filteredEntries := []*ldap.Entry{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.DN, searchBaseDN) {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func (l LDAPOpsHelper) findUser(ctx context.Context, h LDAPOpsHandler, bindDN string, checkGroup bool) (userWhenFound *config.User, resultCode ldap.LDAPResultCode) {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.findUser")
	defer span.End()

	var user config.User

	baseDN := strings.ToLower("," + h.GetBackend().BaseDN)

	// Special Case: bind using UPN
	// Not using mail.ParseAddress/1 because we would allow incorrectly formatted UPNs
	if emailmatcher.MatchString(bindDN) {
		var foundUser bool // = false
		foundUser, user, _ = h.FindUser(ctx, bindDN, true)
		if !foundUser {
			h.GetLog().Info().Str("userprincipalname", bindDN).Msg("User not found")
			return nil, ldap.LDAPResultInvalidCredentials
		}
	} else {
		// parse the bindDN - ensure that the bindDN ends with the BaseDN
		if !strings.HasSuffix(bindDN, baseDN) {
			h.GetLog().Info().Str("binddn", bindDN).Str("basedn", h.GetBackend().BaseDN).Msg("BindDN not part of our BaseDN")
			// h.GetLog().Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
			return nil, ldap.LDAPResultInvalidCredentials
		}
		parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
		groupName := ""
		userName := ""
		if len(parts) == 1 {
			userName = strings.TrimPrefix(parts[0], h.GetBackend().NameFormatAsArray[0]+"=")
		} else if len(parts) == 2 || (len(parts) == 3 && parts[2] == "ou=users") {
			userName = strings.TrimPrefix(parts[0], h.GetBackend().NameFormatAsArray[0]+"=")
			groupName = strings.TrimPrefix(parts[1], h.GetBackend().GroupFormatAsArray[0]+"=")
		} else {
			h.GetLog().Info().Str("binddn", bindDN).Int("numparts", len(parts)).Msg("BindDN should have only one or two parts")
			for _, part := range parts {
				h.GetLog().Info().Str("part", part).Msg("Parts")
			}
			return nil, ldap.LDAPResultInvalidCredentials
		}

		// find the user
		var foundUser bool // = false
		foundUser, user, _ = h.FindUser(ctx, userName, false)
		if !foundUser {
			h.GetLog().Info().Str("username", userName).Msg("User not found")
			return nil, ldap.LDAPResultInvalidCredentials
		}
		if checkGroup {
			// find the group
			var group config.Group // = nil
			var foundGroup bool    // = false
			if groupName != "" {
				foundGroup, group, _ = h.FindGroup(ctx, groupName)
				if !foundGroup {
					h.GetLog().Info().Str("groupname", groupName).Msg("Group not found")
					return nil, ldap.LDAPResultInvalidCredentials
				}
			}
			// validate group membership
			if foundGroup {
				if user.PrimaryGroup != group.GIDNumber {
					h.GetLog().Info().Str("username", userName).Int("primarygroup", user.PrimaryGroup).Int("groupid", group.GIDNumber).Msg("primary group mismatch")
					return nil, ldap.LDAPResultInvalidCredentials
				}
			}
		}
	}
	return &user, ldap.LDAPResultSuccess
}

func (l LDAPOpsHelper) checkCapability(ctx context.Context, user config.User, action string, objects []string) bool {
	// User-level?
	for _, capability := range user.Capabilities {
		if capability.Action == action {
			for _, object := range objects {
				if capability.Object == object {
					return true
				}
			}
		}
	}
	return false
}

// If your query is for, say 'objectClass', then our LDAP
// library will weed out this entry since it does *not* contain an objectclass attribute
// so we are going to re-inject it to keep the LDAP library happy
func (l LDAPOpsHelper) collectRequestedAttributesBack(ctx context.Context, attrs []*ldap.EntryAttribute, searchReq ldap.SearchRequest) []*ldap.EntryAttribute {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.collectRequestedAttributesBack")
	defer span.End()

	attbits := configattributematcher.FindStringSubmatch(searchReq.Filter)
	if len(attbits) == 3 {
		foundattname := false
		for _, attr := range attrs {
			if strings.ToLower(attr.Name) == strings.ToLower(attbits[1]) {
				foundattname = true
				break
			}
		}
		// the ugly hack: we are going to pretend that the requested attribute is in there
		if !foundattname {
			attrs = append(attrs, &ldap.EntryAttribute{Name: attbits[1], Values: []string{attbits[2]}})
		}
	}
	return attrs
}

// return true if we should not process the current operation
func (l LDAPOpsHelper) isInTimeout(ctx context.Context, handler LDAPOpsHandler, conn net.Conn) bool {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.isInTimeout")
	defer span.End()

	cfg := handler.GetCfg()
	if !cfg.Behaviors.LimitFailedBinds {
		return false
	}

	remoteAddr := l.getAddr(ctx, conn)
	now := time.Now()
	info, ok := l.sources[remoteAddr]
	if !ok {
		l.sources[remoteAddr] = &sourceInfo{
			lastSeen:  now,
			failures:  make(chan failedBind, cfg.Behaviors.NumberOfFailedBinds),
			waitUntil: now,
		}
		return false
	}
	// update so that this source does not get pruned
	info.lastSeen = now
	// if we are in a time out...
	if cfg.Behaviors.LimitFailedBinds && info.waitUntil.After(now) {
		return true
	}
	return false
}

func (l LDAPOpsHelper) maybePutInTimeout(ctx context.Context, handler LDAPOpsHandler, conn net.Conn, noteFailure bool) bool {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.maybePutInTimeout")
	defer span.End()

	cfg := handler.GetCfg()
	if !cfg.Behaviors.LimitFailedBinds {
		return false
	}

	remoteAddr := l.getAddr(ctx, conn)
	now := time.Now()
	info, _ := l.sources[remoteAddr]
	// if we have a failed bind...
	if noteFailure {
		info.failures <- failedBind{ts: time.Now()}
		// if we now have 3 failed binds in a row
		if len(info.failures) == cfg.Behaviors.NumberOfFailedBinds {
			// we cannot have more than 3 failed binds in our channel so pop the oldest one
			pruned := <-info.failures
			// if we have 3 failed bind in a row in less than 3 seconds
			if pruned.ts.Add(cfg.Behaviors.PeriodOfFailedBinds * time.Second).After(now) {
				// we will wait for 'n' seconds no matter what happens next
				info.waitUntil = time.Now().Add(cfg.Behaviors.BlockFailedBindsFor * time.Second)
				// purge our failure queue until we resume accepting operations
				for len(info.failures) > 0 {
					<-info.failures
				}
			}
		}
	}
	// Prune old IPs
	// TODO We should ensure that the time between prunings is bigger than the time to determine rapid failed binds
	if l.nextPruning.Before(now) {
		for sourceIP, sourceInfo := range l.sources {
			if sourceInfo.lastSeen.Add(cfg.Behaviors.PruneSourcesOlderThan * time.Second).Before(now) {
				delete(l.sources, sourceIP)
			}
		}
		l.nextPruning = time.Now().Add(cfg.Behaviors.PruneSourceTableEvery * time.Second)
	}
	return false
}

func (l LDAPOpsHelper) getAddr(ctx context.Context, conn net.Conn) string {
	ctx, span := l.tracer.Start(ctx, "handler.LDAPOpsHelper.getAddr")
	defer span.End()

	fullAddr := conn.RemoteAddr().String()
	sep := strings.LastIndex(fullAddr, ":")
	if sep == -1 {
		return fullAddr
	}
	return fullAddr[0:sep]
}
