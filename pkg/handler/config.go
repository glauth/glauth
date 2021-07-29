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
	"sort"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)

type configHandler struct {
	backend     config.Backend
	log         logr.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	attmatcher  *regexp.Regexp
}

// NewConfigHandler creates a new config backed handler
func NewConfigHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	handler := configHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config, // TODO only used to access Users and Groups, move that to dedicated options
		yubikeyAuth: options.YubiAuth,
		attmatcher:  configattributematcher,
	}
	return handler
}

// Bind implements a bind request against the config file
func (h configHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)

	h.log.V(6).Info("Bind request", "binddn", bindDN, "basedn", h.backend.BaseDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.V(2).Info("BindDN not part of our BaseDN", "binddn", bindDN, "basedn", h.backend.BaseDN)
		// h.log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	groupName := ""
	userName := ""
	if len(parts) == 1 {
		userName = strings.TrimPrefix(parts[0], h.backend.NameFormat+"=")
	} else if len(parts) == 2 {
		userName = strings.TrimPrefix(parts[0], h.backend.NameFormat+"=")
		groupName = strings.TrimPrefix(parts[1], h.backend.GroupFormat+"=")
	} else {
		h.log.V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// find the user
	user := config.User{}
	found := false
	for _, u := range h.cfg.Users {
		if strings.EqualFold(u.Name, userName) {
			found = true
			user = u
		}
	}
	if !found {
		h.log.V(2).Info("User not found", "username", userName)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// find the group
	group := config.Group{}
	found = false
	for _, g := range h.cfg.Groups {
		if strings.EqualFold(g.Name, groupName) {
			found = true
			group = g
		}
	}
	if !found {
		h.log.V(2).Info("Group not found", "groupname", groupName)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// validate group membership
	if user.PrimaryGroup != group.UnixID {
		h.log.V(2).Info("primary group mismatch", "username", userName, "primarygroup", user.PrimaryGroup, "groupid", group.UnixID)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	validotp := false

	if len(user.Yubikey) == 0 && len(user.OTPSecret) == 0 {
		validotp = true
	}

	if len(user.Yubikey) > 0 && h.yubikeyAuth != nil {
		if len(bindSimplePw) > 44 {
			otp := bindSimplePw[len(bindSimplePw)-44:]
			yubikeyid := otp[0:12]
			bindSimplePw = bindSimplePw[:len(bindSimplePw)-44]

			if user.Yubikey == yubikeyid {
				_, ok, _ := h.yubikeyAuth.Verify(otp)

				if ok {
					validotp = true
				}
			}
		}
	}

	// Store the full bind password provided before possibly modifying
	// in the otp check
	untouchedBindSimplePw := bindSimplePw

	// Test OTP if exists
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
				h.log.V(6).Info("invalid app credentials", "incorrect stored hash", "(omitted)")
			} else {
				if bcrypt.CompareHashAndPassword(decoded, []byte(untouchedBindSimplePw)) == nil {
					stats.Frontend.Add("bind_successes", 1)
					h.log.V(6).Info("Bind success using app pw", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
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
				h.log.V(6).Info("Attempt to bind app pw failed", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
			} else {
				stats.Frontend.Add("bind_successes", 1)
				h.log.V(6).Info("Bind success using app pw", "index", index, "binddn", bindDN, "src", conn.RemoteAddr())
				return ldap.LDAPResultSuccess, nil
			}
		}
	}

	// Then ensure the OTP is valid before checking
	if !validotp {
		h.log.V(2).Info("invalid OTP token", "binddn", bindDN, "src", conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Now, check the pasword hash
	if user.PassBcrypt != "" {
		decoded, err := hex.DecodeString(user.PassBcrypt)
		if err != nil {
			h.log.V(2).Info("invalid credentials", "incorrect stored hash", "(omitted)")
			return ldap.LDAPResultInvalidCredentials, nil
		}
		if bcrypt.CompareHashAndPassword(decoded, []byte(bindSimplePw)) != nil {
			h.log.V(2).Info("invalid credentials", "binddn", bindDN, "src", conn.RemoteAddr())
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}
	if user.PassSHA256 != "" {
		hash := sha256.New()
		hash.Write([]byte(bindSimplePw))
		if user.PassSHA256 != hex.EncodeToString(hash.Sum(nil)) {
			h.log.V(2).Info("invalid credentials", "binddn", bindDN, "src", conn.RemoteAddr())
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	stats.Frontend.Add("bind_successes", 1)
	h.log.V(6).Info("Bind success", "binddn", bindDN, "src", conn.RemoteAddr())
	return ldap.LDAPResultSuccess, nil
}

// Search implements a search request against the config file
func (h configHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower(h.backend.BaseDN)
	delimitedBaseDN := "," + baseDN
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.V(6).Info("Search request", "binddn", bindDN, "basedn", baseDN, "searchbasedn", searchBaseDN, "src", conn.RemoteAddr(), "scope", searchReq.Scope, "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: Anonymous BindDN not allowed %s", bindDN)
	}

	// special case: querying the root DSE
	if searchReq.Scope == 0 && (searchBaseDN == "" || searchBaseDN == baseDN) {
		h.log.V(6).Info("Search request", "special case", "root DSE")
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
		// ah, but you see, this is not enough because if your query is for, say 'objectClass', then our LDAP
		// library will weed out this entry since it does *not* contain an objectclass attribute
		attbits := h.attmatcher.FindStringSubmatch(searchReq.Filter)
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
		entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
		stats.Frontend.Add("search_successes", 1)
		h.log.V(6).Info("AP: Root Search OK", "filter", searchReq.Filter)
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
	}

	if searchBaseDN == "cn=schema" {
		h.log.V(6).Info("Search request", "special case", "schema discovery")
		entries := []*ldap.Entry{}
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{"schema"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "hasSubordinates", Values: []string{"false"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "modifiersName", Values: []string{"cn=Directory Manager"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "modifyTimeStamp", Values: []string{"Mar 8, 2021, 12:46:29 PM PST (20210308204629Z)"}})
		// Iterate through schema attributes provided in schema/ directory
		filenames, _ := ioutil.ReadDir("schema")
		for _, filename := range filenames {
			file, err := os.Open(filepath.Join("schema", filename.Name()))
			if err != nil {
				return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Schema Error: attribute %s cannot be read", filename)
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
		// This hack again. One more time, and it gets its own function...
		attbits := h.attmatcher.FindStringSubmatch(searchReq.Filter)
		if len(attbits) == 3 {
			foundattname := false
			for _, attr := range attrs {
				if strings.ToLower(attr.Name) == strings.ToLower(attbits[1]) {
					foundattname = true
					break
				}
			}
			if !foundattname {
				attrs = append(attrs, &ldap.EntryAttribute{Name: attbits[1], Values: []string{attbits[2]}})
			}
		}
		entries = append(entries, &ldap.Entry{DN: searchBaseDN, Attributes: attrs})
		stats.Frontend.Add("search_successes", 1)
		h.log.V(6).Info("AP: Schema Discovery OK", "filter", searchReq.Filter)
		return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
	}

	// TODO SHould I move this before our special cases handling (above?)
	if !strings.HasSuffix(bindDN, delimitedBaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: BindDN %s not in our BaseDN %s", bindDN, h.backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.backend.BaseDN)
	}
	// return all users in the config file - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}
	switch filterEntity {
	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		for _, g := range h.cfg.Groups {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{g.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{g.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", g.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", g.UnixID)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: h.getGroupMembers(g.UnixID)})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberIDs(g.UnixID)})
			dn := fmt.Sprintf("cn=%s,%s=groups,%s", g.Name, h.backend.GroupFormat, h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "shadowaccount", "":
		for _, u := range h.cfg.Users {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{u.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{u.Name}})

			if len(u.GivenName) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{u.GivenName}})
			}

			if len(u.SN) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{u.SN}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{h.getGroupName(u.PrimaryGroup)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{fmt.Sprintf("%d", u.UnixID)}})

			if u.Disabled {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
			}

			if len(u.Mail) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{u.Mail}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

			if len(u.LoginShell) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{u.LoginShell}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{"/bin/bash"}})
			}

			if len(u.Homedir) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{u.Homedir}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + u.Name}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", u.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{fmt.Sprintf("%s", u.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: h.getGroupDNs(append(u.OtherGroups, u.PrimaryGroup))})

			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}})

			if len(u.SSHKeys) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.SSHKeyAttr, Values: u.SSHKeys})
			}
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", searchReq.Filter)
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not supported for a static config file
func (h configHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not supported for a static config file
func (h configHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not supported for a static config file
func (h configHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h configHandler) FindUser(userName string) (f bool, u config.User, err error) {
	user := config.User{}
	found := false
	for _, u := range h.cfg.Users {
		if strings.EqualFold(u.Name, userName) {
			found = true
			user = u
		}
	}
	return found, user, nil
}

// Close does not actually close anything, because the config data is kept in memory
func (h configHandler) Close(boundDn string, conn net.Conn) error {
	stats.Frontend.Add("closes", 1)
	return nil
}

func (h configHandler) getGroupMembers(gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
			members[dn] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.UnixID {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getGroupMembers(includegroupid)

					for _, includegroupmember := range includegroupmembers {
						members[includegroupmember] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k, _ := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

func (h configHandler) getGroupMemberIDs(gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	for _, g := range h.cfg.Groups {
		if gid == g.UnixID {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.V(2).Info("Ignoring myself as included group", "groupid", includegroupid)
				} else {
					includegroupmemberids := h.getGroupMemberIDs(includegroupid)

					for _, includegroupmemberid := range includegroupmemberids {
						members[includegroupmemberid] = true
					}
				}
			}
		}
	}

	m := []string{}
	for k, _ := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

// Converts an array of GUIDs into an array of DNs
func (h configHandler) getGroupDNs(gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.UnixID == gid {
				dn := fmt.Sprintf("cn=%s,%s=groups,%s", g.Name, h.backend.GroupFormat, h.backend.BaseDN)
				groups[dn] = true
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.UnixID != gid {
					includegroupdns := h.getGroupDNs([]int{g.UnixID})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k, _ := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}

func (h configHandler) getGroupName(gid int) string {
	for _, g := range h.cfg.Groups {
		if g.UnixID == gid {
			return g.Name
		}
	}
	return ""
}
