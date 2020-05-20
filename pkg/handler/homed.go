package handler

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/search/query"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/go-logr/logr"
	ber "github.com/nmcclain/asn1-ber"
	"github.com/nmcclain/ldap"
	"github.com/tredoe/osutil/user/crypt"
	"gopkg.in/square/go-jose.v2/json"

	// register crypt functions
	_ "github.com/tredoe/osutil/user/crypt/apr1_crypt"
	_ "github.com/tredoe/osutil/user/crypt/md5_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha256_crypt"
	_ "github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

type homedHandler struct {
	index       bleve.Index
	log         logr.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
}

// NewHomedHandler creates a new homed backed handler
// it reads .identity files as described in https://systemd.io/HOME_DIRECTORY/
// the $HOME_ROOT/$USER/.identity files follow the https://systemd.io/USER_RECORD/ spec
// the groups follow the https://systemd.io/GROUP_RECORD/
// this backend directly reads (and writes) these files, ignoring the recommendation to use varlink API: https://systemd.io/USER_GROUP_API/
// groups need their own dir. From the [homectl docs](https://www.freedesktop.org/software/systemd/man/homectl.html):
// > Note that systemd-homed does not manage any groups besides a group matching the user in name and numeric UID/GID. Thus any groups listed
// > here must be registered independently, for example with groupadd(8). If non-existant groups that are listed there are ignored. This
// > option may be used more than once, in which case all specified group lists are combined.

// User includes all fields necessary for posixaccount and some from person and inetorgperson
// while some of these attributes can bu multi value, homed user records uses single value for all of them
// furthermore, storing them as single value in the index allows us to return the results without adding retrieval magic because AFAICT bleve currently does not natively support arrays: https://github.com/blevesearch/bleve/issues/570
type User struct {

	// STRUCTURAL person RFC 2798
	// SN is the surname
	SN string `json:"sn"`
	CN string `json:"cn"` // single value in AD, multi value in other directory implementations, see https://ldapwiki.com/wiki/cn#section-Cn-MicrosoftActiveDirectoryAnomaly1

	Description string `json:"description"`

	// STRUCTURAL inetOrgPerson RFC 2798

	// Mail is a list of RFC822 Mailboxes
	Mail string `json:"mail"`

	// DisplayName is the preferred name of a person to be used when displaying entries (single-value)
	// When displaying an entry, especially within a one-line summary list, it
	// is useful to be able to identify a name to be used.  Since other attri-
	// bute types such as 'cn' are multivalued, an additional attribute type is
	// needed.  Display name is defined for this purpose. (single-value)
	DisplayName string `json:"displayname"`
	GivenName   string `json:"givenname"`

	// EmployeeNumber numerically identifies an employee within an organization RFC 2798
	// Numeric or alphanumeric identifier assigned to a person, typically based
	// on order of hire or association with an organization. (single-value)
	EmployeeNumber string `json:"employeenumber"`

	// EmployeeType is the type of employment for a person
	// Used to identify the employer to employee relationship.  Typical values
	// used will be "Contractor", "Employee", "Intern", "Temp", "External", and
	// "Unknown" but any value may be used.
	EmployeeType string `json:"employeetype"`
	// Initials contains the initials of some or all of an individuals names, but not the surname(s).
	Initials string `json:"initials"`

	// PreferredLanguage is the preferred written or spoken language for a person
	// Used to indicate an individual's preferred written or spoken
	// language.  This is useful for international correspondence or human-
	// computer interaction.  Values for this attribute type MUST conform to
	// the definition of the Accept-Language header field defined in
	// [RFC2068] with one exception:  the sequence "Accept-Language" ":"
	// should be omitted. (single-value)
	PreferredLanguage string `json:"preferredlanguage"`

	// JPEGPhoto is a JPEG image
	// Used to store one or more images of a person using the JPEG File
	// Interchange Format [JFIF].
	// Note that the jpegPhoto attribute type was defined for use in the
	// Internet X.500 pilots but no referencable definition for it could be
	// located.
	JPEGPhoto string `json:"jpegphoto"` // base64 encoded

	// AUXILIARY posixaccount
	// MUST
	// UID is the shorthand name representing the entity (single-value)
	UID           string `json:"uid"` // also shadowAccount MUST
	UIDNumber     uint32 `json:"uidnumber"`
	GidNumber     uint32 `json:"gidnumber"`
	HomeDirectory string `json:"homedirectory"`

	// MAY
	LoginShell string `json:"loginshell"`
	//GECOS        string `json:"gecos"` // left out ... same as displayname
	AuthPassword string `json:"authpassword"` // also shadowAccount

	// AUXILIARY shadowAccount RFC 2307
	// ShadowMin indicates the minimum number of days required between password changes. (single-valued)
	ShadowMin uint32
	// ShadowMax indicates the maximum number of days for which the user password remains valid. (single-valued)
	ShadowMax uint32
	// TODO ShadowExpire indicates the date on which the user login will be disabled. (single-valued)
	ShadowExpire uint32
	// ShadowLastChange indicaten the number of days between January 1, 1970 and the day when the user password was last changed (single-valued)
	ShadowLastChange uint32
	// ShadowFlag not currently in use.
	//ShadowFlag       uint32
	// ShadowWarning indicates the number of days of advance warning given to the user before the user password expires. (single-valued)
	ShadowWarning uint32
	// ShadowInactive indicates the number of days of inactivity allowed for the user. (single-valued)
	ShadowInactive uint32

	// TODO create OID http://oid-info.com/cgi-bin/display?oid=1.3.6.1.4.1.39430&action=display
	// OwnCloudUUID indicates a stable, non reassignable unique identifier for a user or group that does not change when the same resource is returned in subsequent requests (single-valued)
	OwnCloudUUID string `json:"ownclouduuid"`
}

// NewHomedHandler returns a new homed datastore
func NewHomedHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	// read all user and group records

	// for now recreate index on every start
	os.RemoveAll("homed.bleve")

	mapping := bleve.NewIndexMapping()
	index, err := bleve.New("homed.bleve", mapping)
	if err != nil {
		panic(err)
	}

	f, err := os.Open(options.Config.Backend.UserRecordsPath)
	if err != nil {
		options.Logger.Error(err, "could not open user records", "dir", options.Config.Backend.UserRecordsPath)
		panic(err)
	}
	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		options.Logger.Error(err, "could not list user records", "dir", options.Config.Backend.UserRecordsPath)
		panic(err)
	}
	for _, file := range list {
		path := filepath.Join(options.Config.Backend.UserRecordsPath, file.Name(), ".identity")
		if !file.IsDir() {
			options.Logger.Error(err, "not a directory", "file", file)
			continue
		}
		if filepath.Ext(file.Name()) == ".homedir" {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				options.Logger.Error(err, "could not read user record", "path", path)
				continue
			}
			userRecord := map[string]interface{}{}
			err = json.Unmarshal(data, &userRecord)
			if err != nil {
				options.Logger.Error(err, "could not unmarshal user record", "path", path)
				continue
			}
			user := User{}
			for key, element := range userRecord {
				switch strings.ToLower(key) {
				// map the attributes
				case "username":
					if val, ok := element.(string); ok {
						user.CN = val
						user.UID = val
					}
				case "uid":
					if val, ok := element.(uint32); ok {
						user.UIDNumber = val
					}
				case "gid":
					if val, ok := element.(uint32); ok {
						user.GidNumber = val
					}
				case "realname":
					if val, ok := element.(string); ok {
						user.DisplayName = val
					}
				case "emailaddress":
					if val, ok := element.(string); ok {
						user.Mail = val
					}
				case "preferredlanguage":
					if val, ok := element.(string); ok {
						user.PreferredLanguage = val
					}
				case "ownclouduuid":
					if val, ok := element.(string); ok {
						user.OwnCloudUUID = val
					}
				case "homedirectory ": // TODO
				case "imagepath  ": // TODO
				default: // unmapped
				}
			}
			options.Logger.V(6).Info("found user record", "user", user)
			index.Index(user.OwnCloudUUID, user)
		} else {
			options.Logger.V(6).Info("invalid user record name or .identity not found", "path", path)
		}
	}

	// TODO watch folders for new records

	handler := homedHandler{
		index:       index,
		log:         options.Logger,
		cfg:         options.Config,
		yubikeyAuth: options.YubiAuth,
	}
	return handler
}

type privileged struct {
	HashedPassword []string `json:"hashedPassword"`
}

type minimalUserRecord struct {
	UserName   string     `json:"userName"`
	Privileged privileged `json:"privileged"`
}

func (h homedHandler) passwordIsValid(hash string, pwd string) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error(fmt.Errorf("%s", r), "password lib panicked", "hash", hash)
		}
	}()

	c := crypt.NewFromHash(hash)
	err := c.Verify(hash, []byte(pwd))
	if err == nil {
		return true
	}
	return
}

// Bind implements a bind request against the config file
func (h homedHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)

	fmt.Println("Bind request binddn ", bindDN, " basedn ", baseDN, " src ", conn.RemoteAddr())
	h.log.V(6).Info("Bind request", "binddn", bindDN, "basedn", baseDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.V(2).Info("BindDN not part of our BaseDN", "binddn", bindDN, "basedn", h.cfg.Backend.BaseDN)
		// h.log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, baseDN))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	userName := ""
	if len(parts) == 1 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
	} else if len(parts) == 2 {
		userName = strings.TrimPrefix(parts[0], h.cfg.Backend.NameFormat+"=")
	} else {
		h.log.V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// find the user
	path := filepath.Join(h.cfg.Backend.UserRecordsPath, fmt.Sprintf("%s.homedir", userName), ".identity")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		h.log.V(6).Info("User not found", "username", userName, "path", path)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	userRecord := minimalUserRecord{}
	err = json.Unmarshal(data, &userRecord)
	if err != nil {
		h.log.Error(err, "Could not unmarshal user", "username", userName, "path", path)
		return ldap.LDAPResultInvalidCredentials, nil // TODO return other error?
	}
	// double check username
	if userRecord.UserName != userName { // case sensitive
		h.log.Error(err, "username mismatch", "path", path, "expected", userName, "actual", userRecord.UserName)
		return ldap.LDAPResultInvalidCredentials, nil // TODO return other error?
	}

	for i := range userRecord.Privileged.HashedPassword {
		if h.passwordIsValid(userRecord.Privileged.HashedPassword[i], bindSimplePw) {
			stats.Frontend.Add("bind_successes", 1)
			h.log.V(6).Info("Bind success", "binddn", bindDN, "src", conn.RemoteAddr())
			return ldap.LDAPResultSuccess, nil
		} else {
			h.log.Error(err, "Wrong password", "binddn", bindDN, "src", conn.RemoteAddr())
		}
	}
	h.log.Error(err, "wrong password", "username", userName)
	return ldap.LDAPResultInvalidCredentials, nil

}

func parseFilter(f *ber.Packet) (q query.Query, err error) {
	switch ldap.FilterMap[f.Tag] {
	case "Equality Match":
		if len(f.Children) != 2 {
			return nil, errors.New("Equality match must have only two children")
		}
		attribute := strings.ToLower(f.Children[0].Value.(string))
		value := f.Children[1].Value.(string)
		q := bleve.NewTermQuery(value)
		q.SetField(attribute)
		return q, nil
	case "And":
		q := query.NewConjunctionQuery([]query.Query{})
		for _, child := range f.Children {
			subQuery, err := parseFilter(child)
			if err != nil {
				return nil, err
			}
			if subQuery != nil {
				q.AddQuery(subQuery)
			}
		}
		return q, nil
	case "Or":
		q := query.NewDisjunctionQuery([]query.Query{})
		for _, child := range f.Children {
			subQuery, err := parseFilter(child)
			if err != nil {
				return nil, err
			}
			if subQuery != nil {
				q.AddQuery(subQuery)
			}
		}
		return q, nil
	case "Not":
		if len(f.Children) != 1 {
			return nil, errors.New("Not filter must have only one child")
		}
		subQuery, err := parseFilter(f.Children[0])
		if err != nil {
			return nil, err
		}
		q = query.NewBooleanQuery(nil, nil, []query.Query{subQuery})
	}
	return
}

// Search implements a search request against the config file
func (h homedHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	fmt.Println("Search request binddn ", bindDN, " basedn ", baseDN, " src ", conn.RemoteAddr(), " filter '", searchReq.Filter, "'")
	h.log.V(6).Info("Search request", "binddn", bindDN, "basedn", baseDN, "src", conn.RemoteAddr(), "filter", searchReq.Filter)
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

	var query query.Query
	if searchReq.Filter == "(&)" { // see Absolute True and False Filters in https://tools.ietf.org/html/rfc4526#section-2
		query = bleve.NewMatchAllQuery()
	} else {
		var cf *ber.Packet
		cf, err = ldap.CompileFilter(searchReq.Filter)
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
		}
		query, err = parseFilter(cf)
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
		}
		if query == nil { // safeguard
			query = bleve.NewMatchAllQuery()
		}
	}

	h.log.V(6).Info("parsed query", "query", query)
	searchRequest := bleve.NewSearchRequest(query)
	searchRequest.Fields = []string{"cn", "uid", "uidnumber", "gidnumber", "displayname", "mail"}
	searchResult, err := h.index.Search(searchRequest)
	h.log.V(6).Info("result", "result", searchResult)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("Search Error: error parsing filter: %s", searchReq.Filter)
	}

	entries := []*ldap.Entry{}
	for _, hit := range searchResult.Hits {
		h.log.V(6).Info("AP: Search OK", "hit", hit)
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ownclouduuid", Values: []string{hit.ID}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{hit.Fields["cn"].(string)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{hit.Fields["uid"].(string)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{strconv.FormatUint(uint64(hit.Fields["uidnumber"].(float64)), 10)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{strconv.FormatUint(uint64(hit.Fields["gidnumber"].(float64)), 10)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{hit.Fields["displayname"].(string)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{hit.Fields["displayname"].(string)}}) // TODO add phone and location
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{hit.Fields["mail"].(string)}})

		dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, hit.Fields["uid"].(string), h.cfg.Backend.GroupFormat, "TODO", h.cfg.Backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}

	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", searchReq.Filter)
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not supported for a static config file
func (h homedHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not supported for a static config file
func (h homedHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not supported for a static config file
func (h homedHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Close does not actually close anything, because the config data is kept in memory
func (h homedHandler) Close(boundDn string, conn net.Conn) error {
	stats.Frontend.Add("closes", 1)
	return nil
}

func (h homedHandler) getGroupMembers(gid int) []string {
	members := make(map[string]bool)
	for _, u := range h.cfg.Users {
		if u.PrimaryGroup == gid {
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, u.Name, h.cfg.Backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
			members[dn] = true
		} else {
			for _, othergid := range u.OtherGroups {
				if othergid == gid {
					dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, u.Name, h.cfg.Backend.GroupFormat, h.getGroupName(u.PrimaryGroup), h.cfg.Backend.BaseDN)
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

func (h homedHandler) getGroupMemberIDs(gid int) []string {
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
func (h homedHandler) getGroupDNs(gids []int) []string {
	groups := make(map[string]bool)
	for _, gid := range gids {
		for _, g := range h.cfg.Groups {
			if g.UnixID == gid {
				dn := fmt.Sprintf("cn=%s,%s=groups,%s", g.Name, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
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

func (h homedHandler) getGroupName(gid int) string {
	for _, g := range h.cfg.Groups {
		if g.UnixID == gid {
			return g.Name
		}
	}
	return ""
}
