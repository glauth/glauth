package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
	"github.com/msteinert/pam"
	"os/user"
	"os"
	"bufio"
)

func copyBytes(x []byte) []byte {
	y := make([]byte, len(x))
	copy(y, x)
	return y
}

func (h pamHandler)localUserIds() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	lines := bufio.NewReader(file)
	var entries []string
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		fs := strings.Split(string(copyBytes(line)), ":")
		// https://en.wikipedia.org/wiki/Passwd#Password_file
		// expect username:*:uid:gid
		if len(fs) < 3 {
			h.log.V(6).Info(fmt.Sprintf("Unexpected number of fields in /etc/passwd at '%s'", line))
			continue
		}
		entries = append(entries, fs[2])
	}
	return entries, nil
}

type GroupEntry struct {
	Gid string
	MemberNames []string
}

func (h pamHandler)localGroupIds() ([]GroupEntry, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	lines := bufio.NewReader(file)
	var entries []GroupEntry
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		fs := strings.Split(string(copyBytes(line)), ":")
		// https://en.wikipedia.org/wiki/Group_identifier
		// expect group:*:gid
		if len(fs) < 3 {
			h.log.V(6).Info(fmt.Sprintf("Unexpected number of fields in /etc/group at '%s'", line))
			continue
		}
		// prefer FieldsFunc over Split so that we drop empty entries
		splitMembersFunc := func(c rune) bool {
	        return c == ','
		}
		members := strings.FieldsFunc(fs[len(fs)-1], splitMembersFunc)
		entries = append(entries, GroupEntry{fs[2], members})
	}
	return entries, nil
}


type pamHandler struct {
	log      logr.Logger
	cfg      *config.Config
}

func (h pamHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)

	h.log.V(6).Info("Bind request", "binddn", bindDN, "basedn", h.cfg.Backend.BaseDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.V(2).Info("BindDN not part of our BaseDN", "binddn", bindDN, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	groupName := ""
	userName := ""
	if len(parts) == 1 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
	} else if len(parts) == 2 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
		groupName = strings.TrimPrefix(parts[1], h.cfg.Backend.GroupFormat+"=")
	} else {
		h.log.V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// verify the group
	localUser, err := user.Lookup(userName)
	if err != nil {
		// user is unknown
		h.log.V(2).Info("Authentication failed - no such user", "username", userName, "group", groupName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	localGroups, err := localUser.GroupIds()
	if err != nil {
		// user has no groups
		h.log.V(2).Info("Authentication failed - user without groups", "username", userName, "group", groupName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	matchingGroup := false
	for _, gid := range localGroups {
		localGroup, err := user.LookupGroupId(gid)
		if err != nil {
			h.log.V(6).Info("Bad group", "gid", gid, "error", err.Error())
			continue
		}
    	if localGroup.Name == groupName {
    		matchingGroup = true
    		break
    	}
	}
	if !matchingGroup {
		// user has wrong groups
		h.log.V(2).Info("Authentication failed - user not in group", "username", userName, "group", groupName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Note: While there is golang bindings to interface with unix_pam (e.g. github.com/msteinert/pam),
	//		 these have the limitation that only the user running the glauth process is able to authenticate
	//		 unless explicitly spawned as root which is not advisable.
	//	     see discussions on https://mariadb.com/kb/en/authentication-plugin-pam/+comments/334
	//		 see comment in https://github.com/msteinert/pam/blob/master/example_test.go line 22
	//
	// One possible workaround which is fine for the time being is adding the user executing glauth to the 'shadow' group

	// try to login
	h.log.V(6).Info("Trying to authenticate", "username", userName)
	t, err := pam.StartFunc("", userName, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return bindSimplePw, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("Unrecognized PAM message style")
	})

	if err != nil {
		h.log.V(2).Info("Authentication failed", "username", userName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	if err = t.Authenticate(0); err != nil {
		h.log.V(2).Info("Authentication failed", "username", userName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	stats.Frontend.Add("bind_successes", 1)
	h.log.V(6).Info("Bind success", "binddn", bindDN, "basedn", h.cfg.Backend.BaseDN, "src", conn.RemoteAddr())
	return ldap.LDAPResultSuccess, nil
}

func (h pamHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.V(6).Info("Search request", "bindDN", bindDN, "baseDN", baseDN, "searchBaseDN", searchBaseDN, "src", conn.RemoteAddr(), "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: BindDN %s not in our BaseDN %s", bindDN, h.cfg.Backend.BaseDN)
	}
	if len(searchBaseDN) > 0 && !strings.HasSuffix(searchBaseDN, h.cfg.Backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.cfg.Backend.BaseDN)
	}
	// return all users known in the system - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}
	switch filterEntity {
	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		groups, err := h.localGroupIds()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: failed to enumerate users: %s", err.Error())
		}
		for _, g := range groups {
			localGroup, err := user.LookupGroupId(g.Gid)
			if err != nil {
				h.log.V(6).Info("Bad group", "gid", g.Gid, "error", err.Error())
				continue
			}
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{localGroup.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{localGroup.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", localGroup.Name)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%s", localGroup.Gid)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})

			var memberNames []string
			var memberUids []string
			for _, name := range g.MemberNames {
				localUser, err := user.Lookup(name)
				if err != nil {
					h.log.V(6).Info("Bad user", "name", name, "group", localGroup.Name, "error", err.Error())
					continue
				}
				primaryGroup, err := user.LookupGroupId(localUser.Gid)
				if err != nil {
					h.log.V(6).Info("User without primary group", "name", name, "gid", localUser.Gid, "error", err.Error())
					continue
				}
				dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, localUser.Username, h.cfg.Backend.GroupFormat, primaryGroup.Name, h.cfg.Backend.BaseDN)
				memberNames = append(memberNames, dn)
				memberUids = append(memberUids, localUser.Username)
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: memberNames})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: memberUids})

			dn := fmt.Sprintf("cn=%s,%s=groups,%s", localGroup.Name, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "shadowaccount", "":
		users, err := h.localUserIds()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: failed to enumerate users: %s", err.Error())
		}
		for _, u := range users {
			localUser, err := user.LookupId(u)
			if err != nil {
				h.log.V(6).Info("Bad user", "uid", u, "error", err.Error())
				continue
			}
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{localUser.Username}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{localUser.Username}})

			if len(localUser.Name) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{localUser.Name}})
				attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{localUser.Name}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{localUser.Username}})
				attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{localUser.Username}})
			}

			localGroup, err := user.LookupGroupId(localUser.Gid)
			if err != nil {
				h.log.V(6).Info("Bad primary group", "user", localUser.Username, "gid", localUser.Gid, "error", err.Error())
				continue
			}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{localGroup.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{localUser.Uid}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount", "shadowAccount"}})

			if len(localUser.HomeDir) > 0 {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{localUser.HomeDir}})
			} else {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{"/home/" + localUser.Username}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", localUser.Username)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{fmt.Sprintf("%s", localUser.Username)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{localUser.Gid}})

			var localGroupDns []string
			localGroups, err := localUser.GroupIds()
			if err == nil {
				for _, gid := range localGroups {
					userGroup, err := user.LookupGroupId(gid)
					if err != nil {
						h.log.V(6).Info("Bad group", "gid", gid, "error", err.Error())
						continue
					}
					dn := fmt.Sprintf("cn=%s,%s=groups,%s", userGroup.Name, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
					//dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, localUser.Name, h.cfg.Backend.GroupFormat, userGroup.Name, h.cfg.Backend.BaseDN)
					localGroupDns = append(localGroupDns, dn)
				}
				attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: localGroupDns})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowExpire", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowFlag", Values: []string{"134538308"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowInactive", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowLastChange", Values: []string{"11000"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMax", Values: []string{"99999"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowMin", Values: []string{"-1"}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "shadowWarning", Values: []string{"7"}})

			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, localUser.Username, h.cfg.Backend.GroupFormat, localGroup.Name, h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", searchReq.Filter)
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not yet supported for the pam backend
func (h pamHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the pam backend
func (h pamHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the pam backend
func (h pamHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// FindUser with the given username. Called by the ldap backend to authenticate the bind. Optional
func (h pamHandler) FindUser(userName string, searchByUPN bool) (found bool, user config.User, err error) {
	h.log.V(6).Info("FindUser", "userName", userName, "searchByUPN", searchByUPN)
	return false, config.User{}, nil
}

func (h pamHandler) FindGroup(groupName string) (found bool, group config.Group, err error) {
	return false, config.Group{}, nil
}

func (h pamHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

func NewPamHandler(opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	return pamHandler{
		log:      options.Logger,
		cfg:      options.Config,
	}
}