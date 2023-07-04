package plugins

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/nmcclain/ldap"
)

var configattributematcher = regexp.MustCompile(`(?i)\((?P<attribute>[a-zA-Z0-9]+)\s*=\s*(?P<value>.*)\)`)

type SqlBackend interface {
	// Name used by database/sql when loading the driver
	GetDriverName() string
	// Create db/schema if necessary
	CreateSchema(db *sql.DB)
	// Migrate schema if necessary
	MigrateSchema(db *sql.DB, checker func(*sql.DB, string) bool)
	//
	GetPrepareSymbol() string
}

type database struct {
	path string
	cnx  *sql.DB
}

type databaseHandler struct {
	backend     config.Backend
	log         *zerolog.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	sqlBackend  SqlBackend
	database    database
	MemGroups   []config.Group
	ldohelper   handler.LDAPOpsHelper
	attmatcher  *regexp.Regexp
}

func NewDatabaseHandler(sqlBackend SqlBackend, opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// Note: we will never terminate this connection pool.
	db, err := sql.Open(sqlBackend.GetDriverName(), options.Backend.Database)
	if err != nil {
		options.Logger.Error().Err(err).Msg(fmt.Sprintf("unable to open SQL database named '%s'", options.Backend.Database))
		os.Exit(1)
	}
	err = db.Ping()
	if err != nil {
		options.Logger.Error().Err(err).Msg(fmt.Sprintf("unable to communicate with SQL database error: %s", options.Backend.Database))
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
	sqlBackend.MigrateSchema(db, ColumnExists)

	options.Logger.Info().Msg("Database (" + sqlBackend.GetDriverName() + "::" + options.Backend.Database + ") Plugin: Ready")

	return handler
}

func ColumnExists(db *sql.DB, columnName string) bool {
	var found string
	err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(%s) FROM users`, columnName)).Scan(
		&found)
	if err != nil {
		return false
	}
	return true
}

func (h databaseHandler) GetBackend() config.Backend {
	return h.backend
}
func (h databaseHandler) GetLog() *zerolog.Logger {
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

	var disabled int
	err = h.database.cnx.QueryRow(fmt.Sprintf(`
			SELECT u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.disabled
			FROM users u WHERE %s=%s`,
		criterion,
		h.sqlBackend.GetPrepareSymbol()), userName).Scan(
		&user.UIDNumber, &user.PrimaryGroup, &user.PassBcrypt, &user.PassSHA256, &user.OTPSecret, &user.Yubikey, &disabled)
	if err == nil {
		user.Disabled = h.intToBool(disabled)
		if !user.Disabled {
			found = true

			if !h.cfg.Behaviors.IgnoreCapabilities {
				capability := config.Capability{}
				rows, err := h.database.cnx.Query(fmt.Sprintf(`
				SELECT c.action,c.object
				FROM capabilities c WHERE userid=%s`,
					h.sqlBackend.GetPrepareSymbol()), user.UIDNumber)
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
	}

	return found, user, err
}

func (h databaseHandler) FindGroup(groupName string) (f bool, g config.Group, err error) {
	group := config.Group{}
	found := false

	err = h.database.cnx.QueryRow(fmt.Sprintf(`
			SELECT g.gidnumber FROM groups g WHERE lower(name)=%s`, h.sqlBackend.GetPrepareSymbol()), groupName).Scan(
		&group.GIDNumber)
	if err == nil {
		found = true
	}

	return found, group, err
}

func (h databaseHandler) FindPosixAccounts(hierarchy string) (entrylist []*ldap.Entry, err error) {
	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups()
	if err != nil {
		return entries, err
	}

	rows, err := h.database.cnx.Query(`
		SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled,u.sshkeys,u.custattr  
		FROM users u`)
	if err != nil {
		return entries, err
	}
	defer rows.Close()

	var otherGroups string
	var disabled int
	var sshKeys string
	var custattrstr string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UIDNumber, &u.PrimaryGroup, &u.PassBcrypt, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups, &u.GivenName, &u.SN, &u.Mail, &u.LoginShell, &u.Homedir, &disabled, &sshKeys, &custattrstr)
		if err != nil {
			return entries, err
		}
		u.OtherGroups = h.commaListToIntTable(otherGroups)
		u.Disabled = h.intToBool(disabled)
		u.SSHKeys = h.commaListToStringTable(sshKeys)

		entry := h.getAccount(hierarchy, u)

		if custattrstr != "{}" {
			var r map[string]interface{}
			err := json.Unmarshal([]byte(custattrstr), &r)
			if err != nil {
				return entries, err
			}
			for key, attr := range r {
				switch typedattr := attr.(type) {
				case []interface{}:
					var values []string
					for _, v := range typedattr {
						switch typedvalue := v.(type) {
						case string:
							values = append(values, handler.MaybeDecode(typedvalue))
						default:
							values = append(values, handler.MaybeDecode(fmt.Sprintf("%v", typedvalue)))
						}
					}
					entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: key, Values: values})
				default:
					h.log.Warn().Str("key", key).Interface("value", attr).Msg("Unable to map custom attribute")
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (h databaseHandler) FindPosixGroups(hierarchy string) (entrylist []*ldap.Entry, err error) {
	entries := []*ldap.Entry{}

	h.MemGroups, err = h.memoizeGroups()
	if err != nil {
		return entries, err
	}

	for _, g := range h.MemGroups {
		info := h.getGroup(hierarchy, g)
		if hierarchy != "groups" {
			info.DN = strings.Replace(info.DN, ",ou=groups,", fmt.Sprintf(",%s,", hierarchy), 1)
		}
		entries = append(entries, info)
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

func (h databaseHandler) commaListToIntTable(commaList string) []int {
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

func (h databaseHandler) commaListToStringTable(commaList string) []string {
	if len(commaList) == 0 {
		return make([]string, 0)
	}
	return strings.Split(commaList, ",")
}

func (h databaseHandler) memoizeGroups() ([]config.Group, error) {
	workMemGroups := make([]*config.Group, 0)
	rows, err := h.database.cnx.Query(`
		SELECT g1.name,g1.gidnumber,ig.includegroupid
		FROM groups g1 
		LEFT JOIN includegroups ig ON g1.gidnumber=ig.parentgroupid 
		LEFT JOIN groups g2 ON ig.includegroupid=g2.gidnumber`)
	if err != nil {
		return nil, errors.New("Unable to memoize groups list")
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
			return nil, errors.New("Unable to memoize groups list")
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

func (h databaseHandler) getGroupMemberDNs(gid int) []string {
	var insertOuUsers string
	if h.cfg.Behaviors.LegacyVersion > 0 && h.cfg.Behaviors.LegacyVersion <= 20100 {
		insertOuUsers = ""
	} else {
		insertOuUsers = ",ou=users"
	}
	members := make(map[string]bool)

	rows, err := h.database.cnx.Query(`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
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
			dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
			members[dn] = true
		} else {
			u.OtherGroups = h.commaListToIntTable(otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), insertOuUsers, h.backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
		if gid == g.GIDNumber {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid != gid {
					includegroupmembers := h.getGroupMemberDNs(includegroupid)

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
	rows, err := h.database.cnx.Query(`
			SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
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
			u.OtherGroups = h.commaListToIntTable(otherGroups)
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
					h.log.Warn().Msg(fmt.Sprintf("Group: %d - Ignoring myself as included group", includegroupid))
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
				dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormat, g.Name, h.backend.BaseDN)
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
func (h databaseHandler) getGroup(hierarchy string, g config.Group) *ldap.Entry {
	asGroupOfUniqueNames := hierarchy == "ou=groups"

	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{h.backend.GroupFormat, []string{g.Name}})
	attrs = append(attrs, &ldap.EntryAttribute{"description", []string{fmt.Sprintf("%s via LDAP", g.Name)}})
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.GIDNumber)}})
	attrs = append(attrs, &ldap.EntryAttribute{"uniqueMember", h.getGroupMemberDNs(g.GIDNumber)})
	if asGroupOfUniqueNames {
		attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"groupOfUniqueNames", "top"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"memberUid", h.getGroupMemberIDs(g.GIDNumber)})
		attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup", "top"}})
	}
	dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormat, g.Name, h.backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}

func (h databaseHandler) getAccount(hierarchy string, u config.User) *ldap.Entry {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{h.backend.NameFormat, []string{u.Name}})
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
	var dn string
	if hierarchy == "" {
		dn = fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.backend.BaseDN)
	} else {
		dn = fmt.Sprintf("%s=%s,%s=%s,%s,%s", h.backend.NameFormat, u.Name, h.backend.GroupFormat, h.getGroupName(u.PrimaryGroup), hierarchy, h.backend.BaseDN)
	}
	return &ldap.Entry{dn, attrs}
}
