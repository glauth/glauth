package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/handler"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
	"github.com/pquerna/otp/totp"
)

type SqlBackend interface {
	// Name used by database/sql when loading the driver
	GetDriverName() string
	// Create db/schema if necessary
	CreateSchema(db *sql.DB)
	//
	GetPrepareSymbol() string
}

type database struct {
	path string
	cnx  *sql.DB
}

type databaseHandler struct {
	log         *logging.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	sqlBackend  SqlBackend
	database    database
	MemGroups   []config.Group
}

func NewDatabaseHandler(log *logging.Logger, cfg *config.Config, yubikeyAuth *yubigo.YubiAuth, sqlBackend SqlBackend) handler.Handler {

	// Note: we will never terminate this connection pool.
	db, err := sql.Open(sqlBackend.GetDriverName(), cfg.Backend.Database)
	if err != nil {
		log.Fatalf("Unable to open SQL database named '%s' error: %s", cfg.Backend.Database, err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatalf("Unable to communicate with SQL database error: %s", cfg.Backend.Database, err)
	}

	dbInfo := database{
		path: cfg.Backend.Database,
		cnx:  db,
	}

	handler := databaseHandler{
		log:         log,
		cfg:         cfg,
		yubikeyAuth: yubikeyAuth,
		sqlBackend:  sqlBackend,
		database:    dbInfo}

	sqlBackend.CreateSchema(db)

	log.Notice("MySQL Plugin: Ready")

	return handler
}

func (h databaseHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)

	h.log.Debug(fmt.Sprintf("Bind request: bindDN: %s, BaseDN: %s, source: %s", bindDN, h.cfg.Backend.BaseDN, conn.RemoteAddr().String()))

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, h.cfg.Backend.BaseDN))
		// h.log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
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
		h.log.Warning(fmt.Sprintf("Bind Error: BindDN %s should have only one or two parts (has %d)", bindDN, len(parts)))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// find the user
	user := config.User{}
	err = h.database.cnx.QueryRow(fmt.Sprintf(`
			SELECT u.unixid,u.primarygroup,u.passsha256,u.otpsecret,u.yubikey 
			FROM users u WHERE u.name=%s`, h.sqlBackend.GetPrepareSymbol()), userName).Scan(
		&user.UnixID, &user.PrimaryGroup, &user.PassSHA256, &user.OTPSecret, &user.Yubikey)
	if err != nil {
		h.log.Warning(fmt.Sprintf("Bind Error: User %s not found.", userName))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// find the group
	group := config.Group{}
	err = h.database.cnx.QueryRow(fmt.Sprintf(`
			SELECT g.unixid FROM groups g WHERE name=%s`, h.sqlBackend.GetPrepareSymbol()), groupName).Scan(
		&group.UnixID)
	if err != nil {
		h.log.Warning(fmt.Sprintf("Bind Error: Group %s not found.", userName))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	// validate group membership
	if user.PrimaryGroup != group.UnixID {
		h.log.Warning(fmt.Sprintf("Bind Error: User %s primary group is not %s.", userName, groupName))
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
	// Generate a hash of the provided password
	hashFull := sha256.New()
	hashFull.Write([]byte(bindSimplePw))

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
	for index, appPw := range user.PassAppSHA256 {

		if appPw != hex.EncodeToString(hashFull.Sum(nil)) {
			h.log.Debug(fmt.Sprintf("Attempted to bind app pw #%d - failure as %s from %s", index, bindDN, conn.RemoteAddr().String()))
		} else {
			stats.Frontend.Add("bind_successes", 1)
			h.log.Debug("Bind success using app pw #%d as %s from %s", index, bindDN, conn.RemoteAddr().String())
			return ldap.LDAPResultSuccess, nil
		}

	}

	// then check main password with the hash
	hash := sha256.New()
	hash.Write([]byte(bindSimplePw))

	// Then ensure the OTP is valid before checking
	if !validotp {
		h.log.Warning(fmt.Sprintf("Bind Error: invalid OTP token as %s from %s", bindDN, conn.RemoteAddr().String()))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Now, check the hash
	if user.PassSHA256 != hex.EncodeToString(hash.Sum(nil)) {
		h.log.Warning(fmt.Sprintf("Bind Error: invalid credentials as %s from %s", bindDN, conn.RemoteAddr().String()))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	stats.Frontend.Add("bind_successes", 1)
	h.log.Debug(fmt.Sprintf("Bind success as %s from %s", bindDN, conn.RemoteAddr().String()))
	return ldap.LDAPResultSuccess, nil
}

func (h databaseHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.Debug(fmt.Sprintf("Search request as %s from %s for %s", bindDN, conn.RemoteAddr().String(), searchReq.Filter))
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: BindDN %s not in our BaseDN %s", bindDN, h.cfg.Backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.cfg.Backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("Search Error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.cfg.Backend.BaseDN)
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
		h.MemGroups, err = h.memoizeGroups()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: Unable to memoize groups [%s]", err.Error())
		}

		for _, g := range h.MemGroups {
			entries = append(entries, h.getGroup(g))
		}
	case "posixaccount", "":
		h.MemGroups, err = h.memoizeGroups()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: Unable to memoize groups [%s]", err.Error())
		}

		rows, err := h.database.cnx.Query(`
			SELECT u.name,u.unixid,u.primarygroup,u.passsha256,u.otpsecret,u.yubikey,u.othergroups,u.givenname,u.sn,u.mail,u.loginshell,u.homedirectory,u.disabled 
			FROM users u`)
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: Unable to retrieve data [%s]", err.Error())
		}
		defer rows.Close()

		var otherGroups string
		var disabled int
		u := config.User{}
		for rows.Next() {
			err := rows.Scan(&u.Name, &u.UnixID, &u.PrimaryGroup, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups, &u.GivenName, &u.SN, &u.Mail, &u.LoginShell, &u.Homedir, &disabled)
			if err != nil {
				return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: Unable to retrieve data [%s]", err.Error())
			}
			u.OtherGroups = h.commaListToTable(otherGroups)
			u.Disabled = h.intToBool(disabled)

			entries = append(entries, h.getAccount(u))
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.Debug(fmt.Sprintf("AP: Search OK: %s", searchReq.Filter))
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
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
	rows, err := h.database.cnx.Query(`
		SELECT g1.name,g1.unixid,ig.includegroupid
		FROM groups g1 
		LEFT JOIN includegroups ig ON g1.unixid=ig.parentgroupid 
		LEFT JOIN groups g2 ON ig.includegroupid=g2.unixid`)
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
			g := config.Group{Name: groupName, UnixID: groupId}
			pg = &g // To manipulate end of slice
			workMemGroups = append(workMemGroups, &g)
		}
		if includeId.Valid {
			pg.IncludeGroups = append(pg.IncludeGroups, int(includeId.Int64))
		}
	}
	memGroups := make([]config.Group, len(workMemGroups))
	for i, v := range workMemGroups {
		memGroups[i] = config.Group{Name: v.Name, UnixID: v.UnixID, IncludeGroups: v.IncludeGroups}
	}
	return memGroups, nil
}

// Used when looking up Posix Groups
func (h databaseHandler) getGroupMembers(gid int) []string {
	members := make(map[string]bool)

	rows, err := h.database.cnx.Query(`
			SELECT u.name,u.unixid,u.primarygroup,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
	if err != nil {
		// Silent fail... for now
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UnixID, &u.PrimaryGroup, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
		if err != nil {
			return []string{}
		}
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
			members[dn] = true
		} else {
			u.OtherGroups = h.commaListToTable(otherGroups)
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
					members[dn] = true
				}
			}
		}
	}

	for _, g := range h.MemGroups {
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

// Used exclusively when looking up Posix Groups
func (h databaseHandler) getGroupMemberIDs(gid int) []string {
	members := make(map[string]bool)
	rows, err := h.database.cnx.Query(`
			SELECT u.name,u.unixid,u.primarygroup,u.passsha256,u.otpsecret,u.yubikey,u.othergroups
			FROM users u`)
	if err != nil {
		// Silent fail... for now
		return []string{}
	}
	defer rows.Close()

	var otherGroups string
	u := config.User{}
	for rows.Next() {
		err := rows.Scan(&u.Name, &u.UnixID, &u.PrimaryGroup, &u.PassSHA256, &u.OTPSecret, &u.Yubikey, &otherGroups)
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
		if gid == g.UnixID {
			for _, includegroupid := range g.IncludeGroups {
				if includegroupid == gid {
					h.log.Warning(fmt.Sprintf("Group: %d - Ignoring myself as included group", includegroupid))
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

// Invoked for every user being returned from our database
func (h databaseHandler) getGroupDNs(gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.MemGroups {
			if g.UnixID == gid {
				dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, h.cfg.Backend.BaseDN)
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

// Invoked for every user being returned from our database
func (h databaseHandler) getGroupName(gid int) string {
	for _, g := range h.MemGroups {
		if g.UnixID == gid {
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
	attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.UnixID)}})
	attrs = append(attrs, &ldap.EntryAttribute{"objectClass", []string{"posixGroup"}})
	attrs = append(attrs, &ldap.EntryAttribute{"uniqueMember", h.getGroupMembers(g.UnixID)})
	attrs = append(attrs, &ldap.EntryAttribute{"memberUid", h.getGroupMemberIDs(g.UnixID)})
	dn := fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, h.cfg.Backend.BaseDN)
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
	attrs = append(attrs, &ldap.EntryAttribute{"uidNumber", []string{fmt.Sprintf("%d", u.UnixID)}})

	if u.Disabled {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"inactive"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{"accountStatus", []string{"active"}})
	}

	if len(u.Mail) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{"mail", []string{u.Mail}})
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
	dn := fmt.Sprintf("cn=%s,ou=%s,%s", u.Name, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
	return &ldap.Entry{dn, attrs}
}
