package main

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/handler"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)

type SqlBackend interface {
	// Name used by database/sql when loading the driver
	GetDriverName() string
	// Create db/schema if necessary
	CreateSchema(db *sql.DB)
	// Find user query
	FindUserQuery(criterion string) string
	// Find group query
	FindGroupQuery() string
	// Find posix users query
	FindPosixAccountsQuery() string
	// Memoize all groups query
	MemoizeGroupsQuery() string
	// Get group members query
	GetGroupMembersQuery() string
	// Get group member IDs query
	GetGroupMemberIDsQuery() string
	// Get User Capabilities Query
	GetUserCapabilitiesQuery() string
}

type database struct {
	path string
	cnx  *sql.DB
}

type databaseHandler struct {
	backend     config.Backend
	log         logr.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	sqlBackend  SqlBackend
	database    database
	MemGroups   []config.Group
	ldohelper   handler.LDAPOpsHelper
	attmatcher  *regexp.Regexp
}

// func NewDatabaseHandler_deprecated(log *logging.Logger, cfg *config.Config, yubikeyAuth *yubigo.YubiAuth, sqlBackend SqlBackend) handler.Handler {
func NewDatabaseHandler(sqlBackend SqlBackend, opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// Note: we will never terminate this connection pool.
	db, err := sql.Open(sqlBackend.GetDriverName(), options.Backend.Database)
	if err != nil {
		options.Logger.Error(err, "Unable to open SQL database named '%s' error: %s", options.Backend.Database)
		os.Exit(1)
	}
	err = db.Ping()
	if err != nil {
		options.Logger.Error(err, "Unable to communicate with SQL database error: %s", options.Backend.Database)
		os.Exit(1)
	}

	dbInfo := database{
		path: options.Backend.Database,
		cnx:  db,
	}

	handler := databaseHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config,
		yubikeyAuth: options.YubiAuth,
		sqlBackend:  sqlBackend,
		database:    dbInfo,
		ldohelper:   options.LDAPHelper,
		attmatcher:  configattributematcher}

	sqlBackend.CreateSchema(db)

	options.Logger.V(3).Info("Database (" + sqlBackend.GetDriverName() + "::" + options.Backend.Database + ") Plugin: Ready")

	return handler
}

func (h databaseHandler) GetBackend() config.Backend {
	return h.backend
}
func (h databaseHandler) GetLog() logr.Logger {
	return h.log
}
func (h databaseHandler) GetCfg() *config.Config {
	return h.cfg
}
func (h databaseHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return h.yubikeyAuth
}

func (h databaseHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	return h.ldohelper.Bind(h, bindDN, bindSimplePw, conn)
}

func (h databaseHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	return h.ldohelper.Search(h, bindDN, searchReq, conn)
}

// Add is not yet supported for the sql backend
func (h databaseHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the sql backend
func (h databaseHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the sql backend
func (h databaseHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h databaseHandler) FindUser(userName string, searchByUPN bool) (f bool, u config.User, err error) {
	var criterion string
	if searchByUPN {
		criterion = "lower(u.mail)"
	} else {
		criterion = "lower(u.name)"
	}

	user := config.User{}
	found := false

	err = h.database.cnx.QueryRow(h.sqlBackend.FindUserQuery(criterion), userName).Scan(
		&user.UIDNumber, &user.PrimaryGroup, &user.PassBcrypt, &user.PassSHA256, &user.OTPSecret, &user.Yubikey)
	if err == nil {
		found = true

		if !h.cfg.Behaviors.IgnoreCapabilities {
			capability := config.Capability{}
			rows, err := h.database.cnx.Query(h.sqlBackend.GetUserCapabilitiesQuery(), user.UIDNumber)
			if err == nil {
				for rows.Next() {
					err := rows.Scan(&capability.Action, &capability.Object)
					if err == nil {
						user.Capabilities = append(user.Capabilities, capability)
					}
				}
			}
			defer rows.Close()
		}
	}
	return found, user, err
}

func (h databaseHandler) FindGroup(groupName string) (f bool, g config.Group, err error) {
	group := config.Group{}
	found := false

	err = h.database.cnx.QueryRow(h.sqlBackend.FindGroupQuery(), groupName).Scan(
		&group.GIDNumber)
	if err == nil {
		found = true
	}

	return found, group, err
}

func (h databaseHandler) FindPosixAccounts() (entrylist []*ldap.Entry, err error) {
	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups()
	if err != nil {
		return entries, err
	}

	rows, err := h.database.cnx.Query(h.sqlBackend.FindPosixAccountsQuery())
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	var otherGroups string
	var disabled int
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups, &u.GivenName, &u.SN, &u.Mail, &u.LoginShell, &u.Homedir, &disabled)
		if err != nil {
			return entries, err
		}
		u.OtherGroups = h.commaListToTable(otherGroups)
		u.Disabled = h.intToBool(disabled)

		entries = append(entries, h.getAccount(u))
	}

	return entries, nil
}

func (h databaseHandler) FindPosixGroups() (entrylist []*ldap.Entry, err error) {
	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups()
	if err != nil {
		return entries, err
	}

	for _, g := range h.MemGroups {
		entries = append(entries, h.getGroup(g))
	}

	return entries, nil
}

func (h databaseHandler) Close(boundDn string, conn net.Conn) error {
	stats.Frontend.Add("closes", 1)
	return nil
}

func (h databaseHandler) intToBool(value int) bool {
	if value == 0 {
		return false
	}
	return true
}

func (h databaseHandler) commaListToTable(commaList string) []int {
	if len(commaList) == 0 {
		return make([]int, 0)
	}
	rowsAsStrings := strings.Split(commaList, ",")
	rowsAsInts := make([]int, len(rowsAsStrings))
	for i, v := range rowsAsStrings {
		iv, err := strconv.Atoi(v)
		if err != nil {
			return rowsAsInts
		}
		rowsAsInts[i] = iv
	}
	return rowsAsInts
}

func (h databaseHandler) memoizeGroups() ([]config.Group, error) {
	workMemGroups := make([]*config.Group, 0)
	rows, err := h.database.cnx.Query(h.sqlBackend.MemoizeGroupsQuery())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groupName string
	var groupId int
	var includeId sql.NullInt64 // Store includeid from left join
	var pg *config.Group
	recentId := -1 // id of recently updated group
	for rows.Next() {
		err := rows.Scan(&groupName, &groupId, &includeId)
		if err != nil {
			return nil, err
		}
		if recentId != groupId {
			recentId = groupId
			g := config.Group{Name: groupName, GIDNumber: groupId}
			pg = &g // To manipulate end of slice
			workMemGroups = append(workMemGroups, &g)
		}
		if includeId.Valid {
			pg.IncludeGroups = append(pg.IncludeGroups, int(includeId.Int64))
		}
	}
	memGroups := make([]config.Group, len(workMemGroups))
	for i, v := range workMemGroups {
		memGroups[i] = config.Group{Name: v.Name, GIDNumber: v.GIDNumber, IncludeGroups: v.IncludeGroups}
	}
	return memGroups, nil
}

// Used when looking up Posix Groups
func (h databaseHandler) getGroupMembers(gid int) []string {
	members := make(map[string]bool)

	rows, err := h.database.cnx.Query(h.sqlBackend.GetGroupMembersQuery(), gid)
	if err != nil {
		// Silent fail... for now
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
			members[dn] = true
		} else {
			u.OtherGroups = h.commaListToTable(otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
		if gid == g.GIDNumber {
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
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)
	return m
}

// Used exclusively when looking up Posix Groups
func (h databaseHandler) getGroupMemberIDs(gid int) []string {
	members := make(map[string]bool)
	rows, err := h.database.cnx.Query(h.sqlBackend.GetGroupMemberIDsQuery())
	if err != nil {
		// Silent fail... for now
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}
		if u.PrimaryGroup == gid {
			members[u.Name] = true
		} else {
			u.OtherGroups = h.commaListToTable(otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					members[u.Name] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.V(3).Info(fmt.Sprintf("Group: %d - Ignoring myself as included group", includegroupid))
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
	for k := range members {
		m = append(m, k)
	}

	sort.Strings(m)

	return m
}

// Invoked for every user being returned from our database
func (h databaseHandler) getGroupDNs(gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.MemGroups {
			if g.GIDNumber == gid {
				dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, h.backend.BaseDN)
				groups[dn] = true
			}

			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid && g.GIDNumber != gid {
					includegroupdns := h.getGroupDNs([]int{g.GIDNumber})

					for _, includegroupdn := range includegroupdns {
						groups[includegroupdn] = true
					}
				}
			}
		}
	}

	g := []string{}
	for k := range groups {
		g = append(g, k)
	}

	sort.Strings(g)

	return g
}

// Invoked for every user being returned from our database
func (h databaseHandler) getGroupName(gid int) string {
	for _, g := range h.MemGroups {
		if g.GIDNumber == gid {
			return g.Name
		}
	}
	return ""
}

// Toolbox
func (h databaseHandler) getGroup(g config.Group) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{g.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s via LDAP", g.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.GIDNumber)}})
	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup"}})
	attrs = append(attrs, &ldap.EntryAttribute{"uniqueMember", h.getGroupMembers(g.GIDNumber)})
	attrs = append(attrs, &ldap.EntryAttribute{"memberUid", h.getGroupMemberIDs(g.GIDNumber)})
	dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, h.backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}

func (h databaseHandler) getAccount(u config.User) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{"cn", []string{u.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"uid", []string{u.Name}})

	if len(u.GivenName) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"givenName", []string{u.GivenName}})
	}

	if len(u.SN) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"sn", []string{u.SN}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"ou", []string{h.getGroupName(u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{"uidNumber", []string{fmt.Sprintf("%d", u.UIDNumber)}})

	if u.Disabled {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"inactive"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"active"}})
	}

	if len(u.Mail) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"mail", []string{u.Mail}})
		attrs = append(attrs, &ldap.EntryAttribute{"userPrincipalName", []string{u.Mail}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixAccount"}})

	if len(u.LoginShell) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{u.LoginShell}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"loginShell", []string{"/bin/bash"}})
	}

	if len(u.Homedir) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{u.Homedir}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"homeDirectory", []string{"/home/" + u.Name}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gecos", []string{fmt.Sprintf("%s via LDAP", u.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", u.PrimaryGroup)}})
	attrs = append(attrs, &ldap.EntryAttribute{"memberOf", h.getGroupDNs(append(u.OtherGroups, u.PrimaryGroup))})
	if len(u.SSHKeys) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"sshPublicKey", u.SSHKeys})
	}
	dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}

func main() {}
