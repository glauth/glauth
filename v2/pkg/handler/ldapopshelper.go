package handler

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)
var emailmatcher = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

type LDAPOpsHandler interface {
	GetBackend() config.Backend
	GetLog() logr.Logger
	GetCfg() *config.Config
	GetYubikeyAuth() *yubigo.YubiAuth

	FindUser(userName string, searchByUPN bool) (f bool, u config.User, err error)
	FindGroup(groupName string) (f bool, g config.Group, err error)
	FindPosixAccounts(hierarchy string) (entrylist []*ldap.Entry, err error)
	FindPosixGroups(hierarchy string) (entrylist []*ldap.Entry, err error)
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
}

func NewLDAPOpsHelper() LDAPOpsHelper {
	helper := LDAPOpsHelper{
		sources:     make(map[string]*sourceInfo),
		nextPruning: time.Now(),
	}
	return helper
}

func (l LDAPOpsHelper) Bind(h LDAPOpsHandler, bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	if l.isInTimeout(h, conn) {
		return ldap.LDAPResultUnwillingToPerform, nil
	}

	bindDN = strings.ToLower(bindDN)

	h.GetLog().V(6).Info("Bind request", "binddn", bindDN, "basedn", h.GetBackend().BaseDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)

	// Special Case: bind as anonymous
	if bindDN == "" && bindSimplePw == "" {
		stats.Frontend.Add("bind_successes", 1)
		h.GetLog().V(6).Info("Anonymous Bind success", "src", conn.RemoteAddr())
		return ldap.LDAPResultSuccess, nil
	}

	user, ldapcode := l.findUser(h, bindDN, true /* checkGroup */)
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
				h.GetLog().V(6).Info("invalid app credentials", "incorrect stored hash", "(omitted)")
			} else {
				if bcrypt.CompareHashAndPassword(decoded, []byte(untouchedBindSimplePw)) == nil {
					stats.Frontend.Add("bind_successes", 1)
					h.GetLog().V(6).Info("Bind success using app pw", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
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
				h.GetLog().V(6).Info("Attempt to bind app pw failed", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
			} else {
				stats.Frontend.Add("bind_successes", 1)
				h.GetLog().V(6).Info("Bind success using app pw", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
				return ldap.LDAPResultSuccess, nil
			}
		}
	}

	// Then ensure the OTP is valid before checking
	if !validotp {
		h.GetLog().V(2).Info("invalid OTP token", "binddn", bindDN, "src", conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Now, check the pasword hash
	if user.PassBcrypt != "" {
		decoded, err := hex.DecodeString(user.PassBcrypt)
		if err != nil {
			h.GetLog().V(2).Info("invalid credentials", "incorrect stored hash", "(omitted)")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		if bcrypt.CompareHashAndPassword(decoded, []byte(bindSimplePw)) != nil {
			h.GetLog().V(2).Info("invalid credentials", "binddn", bindDN, "src", conn.RemoteAddr())
			l.maybePutInTimeout(h, conn, true)
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}
	if user.PassSHA256 != "" {
		hash := sha256.New()
		hash.Write([]byte(bindSimplePw))
		if user.PassSHA256 != hex.EncodeToString(hash.Sum(nil)) {
			h.GetLog().V(2).Info("invalid credentials", "binddn", bindDN, "src", conn.RemoteAddr())
			l.maybePutInTimeout(h, conn, true)
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	stats.Frontend.Add("bind_successes", 1)
	h.GetLog().V(6).Info("Bind success", "binddn", bindDN, "src", conn.RemoteAddr())
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
func (l LDAPOpsHelper) Search(h LDAPOpsHandler, bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	if l.isInTimeout(h, conn) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultUnwillingToPerform}, fmt.Errorf("Source is in a timeout")
	}

	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower(h.GetBackend().BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)

	anonymous := len(bindDN) < 1

	var boundUser *config.User
	var ldapcode ldap.LDAPResultCode

	if !anonymous {
		if bindDN, boundUser, ldapcode = l.searchCheckBindDN(h, baseDN, bindDN, anonymous); ldapcode != ldap.LDAPResultSuccess {
			return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Search Error: Potential bypass of BindDN %s", bindDN)
		}
	}

	h.GetLog().V(6).Info("Search request", "binddn", bindDN, "basedn", baseDN, "searchbasedn", searchBaseDN, "src", conn.RemoteAddr(), "scope", searchReq.Scope, "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)

	switch entries, ldapcode := l.searchMaybeRootDSEQuery(h, baseDN, searchBaseDN, searchReq, anonymous); ldapcode {
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

	switch entries, ldapcode, attributename := l.searchMaybeSchemaQuery(h, baseDN, searchBaseDN, searchReq, anonymous); ldapcode {
	case ldap.LDAPResultOperationsError:
		return ldap.ServerSearchResult{ResultCode: ldapcode}, fmt.Errorf("Schema Error: attribute %s cannot be read", attributename)
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
	if !h.GetCfg().Behaviors.IgnoreCapabilities && !l.checkCapability(*boundUser, "search", []string{"*", searchBaseDN}) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: no capability allowing BindDN %s to perform search in %s", bindDN, searchBaseDN)
	}

	switch entries, ldapcode := l.searchMaybeTopLevelNodes(h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybeTopLevelGroupsNode(h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybeTopLevelUsersNode(h, baseDN, searchBaseDN, searchReq); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}

	switch entries, ldapcode := l.searchMaybePosixGroups(h, baseDN, searchBaseDN, searchReq, filterEntity); ldapcode {
	case ldap.LDAPResultSuccess:
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	switch entries, ldapcode := l.searchMaybePosixAccounts(h, baseDN, searchBaseDN, searchReq, filterEntity); ldapcode {
	case ldap.LDAPResultSuccess:
		stats.Frontend.Add("search_successes", 1)
		h.GetLog().V(6).Info("AP: Search OK", "filter", searchReq.Filter)
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldapcode}, nil
	}

	// So, this should be an ERROR condition! Right..?
	entries := []*ldap.Entry{}
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Returns: LDAPResultSuccess or anay ldap code returned by findUser
func (l LDAPOpsHelper) searchCheckBindDN(h LDAPOpsHandler, baseDN string, bindDN string, anonymous bool) (newBindDN string, boundUser *config.User, ldapresultcode ldap.LDAPResultCode) {
	boundUser, ldapcode := l.findUser(h, bindDN, false /* checkGroup */)
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
func (l LDAPOpsHelper) searchMaybeRootDSEQuery(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, anonymous bool) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	if searchBaseDN != "" {
		return nil, ldap.LDAPResultOther // OK
	}
	/// Only base scope searches allowed if no basedn is provided
	if searchReq.Scope != ldap.ScopeBaseObject {
		h.GetLog().V(2).Info("Search Error: No BaseDN provided", "src", searchReq.Controls)
		return nil, ldap.LDAPResultUnwillingToPerform // KO
	}
	if anonymous && !h.GetBackend().AnonymousDSE {
		return nil, ldap.LDAPResultInsufficientAccessRights // KO
	}

	h.GetLog().V(6).Info("Search request", "special case", "root DSE")
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
	attrs = l.collectRequestedAttributesBack(attrs, searchReq)
	entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Root Search OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

// Search and return the information, after indirection from the RootDSE
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
func (l LDAPOpsHelper) searchMaybeSchemaQuery(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, anonymous bool) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode, attributename *string) {
	if searchBaseDN != "cn=schema" {
		return nil, ldap.LDAPResultOther, nil // OK
	}

	h.GetLog().V(6).Info("Search request", "special case", "schema discovery")
	entries := []*ldap.Entry{}
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{"schema"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "hasSubordinates", Values: []string{"false"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "modifiersName", Values: []string{"cn=Directory Manager"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "modifyTimeStamp", Values: []string{"Mar 8, 2021, 12:46:29 PM PST (20210308204629Z)"}})
	// Iterate through schema attributes provided in schema/ directory
	filenames, _ := ioutil.ReadDir("schema")
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
	attrs = l.collectRequestedAttributesBack(attrs, searchReq)
	entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Schema Discovery OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess, nil
}

// Retrieve the top-levell nodes, i.e. the baseDN, groups, members...
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelNodes(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	if baseDN != searchBaseDN {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().V(6).Info("Search request", "special case", "top-level browse")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelRootNode(searchBaseDN))
	}
	entries = append(entries, l.topLevelGroupsNode(searchBaseDN, "groups"))
	entries = append(entries, l.topLevelUsersNode(searchBaseDN))
	if searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups("ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)

		userentries, err := h.FindPosixAccounts("ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Top-Level Browse OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

// Search starting from and including the ou=groups node
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelGroupsNode(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	if searchBaseDN != fmt.Sprintf("ou=groups,%s", baseDN) {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().V(6).Info("Search request", "special case", "top-level groups node")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelGroupsNode(searchBaseDN, "groups"))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups("ou=groups")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Top-Level Groups Browse OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

// Search starting from and including the ou=users node
// Returns: LDAPResultSuccess, LDAPResultOther
func (l LDAPOpsHelper) searchMaybeTopLevelUsersNode(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	if searchBaseDN != fmt.Sprintf("ou=users,%s", baseDN) {
		return nil, ldap.LDAPResultOther // OK
	}
	h.GetLog().V(6).Info("Search request", "special case", "top-level users node")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		entries = append(entries, l.topLevelUsersNode(searchBaseDN))
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups("ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, groupentries...)
	}
	if searchReq.Scope == ldap.ScopeWholeSubtree {
		userentries, err := h.FindPosixAccounts("ou=users")
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, userentries...)
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Top-Level Users Browse OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

// Look up posixgroup entries, either through objectlass or parent is ou=groups or ou=users
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
func (l LDAPOpsHelper) searchMaybePosixGroups(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, filterEntity string) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	hierarchy := "ou=groups"
	if filterEntity != "posixgroup" {
		bits := strings.Split(strings.Replace(searchBaseDN, baseDN, "", 1), ",")
		if len(bits) != 3 || (bits[1] != "ou=groups" && bits[1] != "ou=users") {
			return nil, ldap.LDAPResultOther // OK
		}
		hierarchy = bits[1]
	}
	h.GetLog().V(6).Info("Search request", "special case", "posix groups")
	entries := []*ldap.Entry{}
	if searchReq.Scope == ldap.ScopeBaseObject || searchReq.Scope == ldap.ScopeWholeSubtree {
		groupentries, err := h.FindPosixGroups(hierarchy)
		if err != nil {
			return nil, ldap.LDAPResultOperationsError
		}
		entries = append(entries, l.preFilterEntries(searchBaseDN, groupentries)...)
	}
	if searchReq.Scope == ldap.ScopeSingleLevel || searchReq.Scope == ldap.ScopeWholeSubtree {
		if hierarchy == "ou=users" {
			userentries, err := h.FindPosixAccounts("ou=users")
			if err != nil {
				return nil, ldap.LDAPResultOperationsError
			}
			entries = append(entries, l.preFilterEntries(searchBaseDN, userentries)...)
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Posix Groups Search OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

// Lookup posixaccount entries
// Returns: LDAPResultSuccess, LDAPResultOther, LDAPResultOperationsError
// This function ignores scopes... for now
func (l LDAPOpsHelper) searchMaybePosixAccounts(h LDAPOpsHandler, baseDN string, searchBaseDN string, searchReq ldap.SearchRequest, filterEntity string) (resultentries []*ldap.Entry, ldapresultcode ldap.LDAPResultCode) {
	switch filterEntity {
	case "posixaccount", "shadowaccount", "":
		h.GetLog().V(6).Info("Search request", "default case", filterEntity)
	default:
		return nil, ldap.LDAPResultOther // OK
	}

	// FixUp: we may be in the process of browsing users from a group ou
	hierarchyString := ""
	if strings.HasSuffix(searchBaseDN, fmt.Sprintf("ou=users,%s", baseDN)) {
		hierarchyString = "ou=users"
	}

	entries, err := h.FindPosixAccounts(hierarchyString)
	if err != nil {
		return nil, ldap.LDAPResultOperationsError
	}
	stats.Frontend.Add("search_successes", 1)
	h.GetLog().V(6).Info("AP: Account Search OK", "filter", searchReq.Filter)
	return entries, ldap.LDAPResultSuccess
}

func (l LDAPOpsHelper) topLevelRootNode(searchBaseDN string) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	dnBits := strings.Split(searchBaseDN, ",")
	for _, dnBit := range dnBits {
		chunk := strings.Split(dnBit, "=")
		attrs = append(attrs, &ldap.EntryAttribute{Name: chunk[0], Values: []string{chunk[1]}})
	}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"organizationalUnit", "dcObject", "top"}})
	return &ldap.Entry{DN: searchBaseDN, Attributes: attrs}
}

func (l LDAPOpsHelper) topLevelGroupsNode(searchBaseDN string, hierarchy string) *ldap.Entry {
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

func (l LDAPOpsHelper) topLevelUsersNode(searchBaseDN string) *ldap.Entry {
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
func (l LDAPOpsHelper) preFilterEntries(searchBaseDN string, entries []*ldap.Entry) (resultentries []*ldap.Entry) {
	filteredEntries := []*ldap.Entry{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.DN, searchBaseDN) {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
}

func (l LDAPOpsHelper) findUser(h LDAPOpsHandler, bindDN string, checkGroup bool) (userWhenFound *config.User, resultCode ldap.LDAPResultCode) {

	var user config.User

	baseDN := strings.ToLower("," + h.GetBackend().BaseDN)

	// Special Case: bind using UPN
	// Not using mail.ParseAddress/1 because we would allow incorrectly formatted UPNs
	if emailmatcher.MatchString(bindDN) {
		var foundUser bool // = false
		foundUser, user, _ = h.FindUser(bindDN, true)
		if !foundUser {
			h.GetLog().V(2).Info("User not found", "userprincipalname", bindDN)
			return nil, ldap.LDAPResultInvalidCredentials
		}
	} else {
		// parse the bindDN - ensure that the bindDN ends with the BaseDN
		if !strings.HasSuffix(bindDN, baseDN) {
			h.GetLog().V(2).Info("BindDN not part of our BaseDN", "binddn", bindDN, "basedn", h.GetBackend().BaseDN)
			// h.GetLog().Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
			return nil, ldap.LDAPResultInvalidCredentials
		}
		parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
		groupName := ""
		userName := ""
		if len(parts) == 1 {
			userName = strings.TrimPrefix(parts[0], h.GetBackend().NameFormat+"=")
		} else if len(parts) == 2 || (len(parts) == 3 && parts[2] == fmt.Sprintf("%s=users", h.GetBackend().GroupFormat)) {
			userName = strings.TrimPrefix(parts[0], h.GetBackend().NameFormat+"=")
			groupName = strings.TrimPrefix(parts[1], h.GetBackend().GroupFormat+"=")
		} else {
			h.GetLog().V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
			for _, part := range parts {
				h.GetLog().V(2).Info("Parts", "part", part)
			}
			return nil, ldap.LDAPResultInvalidCredentials
		}

		// find the user
		var foundUser bool // = false
		foundUser, user, _ = h.FindUser(userName, false)
		if !foundUser {
			h.GetLog().V(2).Info("User not found", "username", userName)
			return nil, ldap.LDAPResultInvalidCredentials
		}
		if checkGroup {
			// find the group
			var group config.Group // = nil
			var foundGroup bool    // = false
			if groupName != "" {
				foundGroup, group, _ = h.FindGroup(groupName)
				if !foundGroup {
					h.GetLog().V(2).Info("Group not found", "groupname", groupName)
					return nil, ldap.LDAPResultInvalidCredentials
				}
			}
			// validate group membership
			if foundGroup {
				if user.PrimaryGroup != group.GIDNumber {
					h.GetLog().V(2).Info("primary group mismatch", "username", userName, "primarygroup", user.PrimaryGroup, "groupid", group.GIDNumber)
					return nil, ldap.LDAPResultInvalidCredentials
				}
			}
		}
	}
	return &user, ldap.LDAPResultSuccess
}

func (l LDAPOpsHelper) checkCapability(user config.User, action string, objects []string) bool {
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
func (l LDAPOpsHelper) collectRequestedAttributesBack(attrs []*ldap.EntryAttribute, searchReq ldap.SearchRequest) []*ldap.EntryAttribute {
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
func (l LDAPOpsHelper) isInTimeout(handler LDAPOpsHandler, conn net.Conn) bool {
	cfg := handler.GetCfg()
	if !cfg.Behaviors.LimitFailedBinds {
		return false
	}

	remoteAddr := l.getAddr(conn)
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

func (l LDAPOpsHelper) maybePutInTimeout(handler LDAPOpsHandler, conn net.Conn, noteFailure bool) bool {
	cfg := handler.GetCfg()
	if !cfg.Behaviors.LimitFailedBinds {
		return false
	}

	remoteAddr := l.getAddr(conn)
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

func (l LDAPOpsHelper) getAddr(conn net.Conn) string {
	fullAddr := conn.RemoteAddr().String()
	sep := strings.LastIndex(fullAddr, ":")
	if sep == -1 {
		return fullAddr
	}
	return fullAddr[0:sep]
}
