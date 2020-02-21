package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/nmcclain/ldap"
	msgraph "github.com/yaegashi/msgraph.go/v1.0"
)

type ownCloudSession struct {
	user        string
	password    string
	baseUrl     string
	useGraphAPI bool
}
type ownCloudHandler struct {
	cfg      *config.Config
	meUrl    string
	sessions map[string]ownCloudSession
	lock     sync.Mutex
}

func (o ownCloudHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + o.cfg.Backend.BaseDN)

	log.Debug(fmt.Sprintf("Bind request: bindDN: %s, BaseDN: %s, source: %s", bindDN, o.cfg.Backend.BaseDN, conn.RemoteAddr().String()))

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		log.Warning(fmt.Sprintf("Bind Error: BindDN %s not our BaseDN %s", bindDN, o.cfg.Backend.BaseDN))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) > 2 {
		log.Warning(fmt.Sprintf("Bind Error: BindDN %s should have only one or two parts (has %d)", bindDN, len(parts)))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	userName := strings.TrimPrefix(parts[0], "cn=")

	// try to login
	if !o.login(userName, bindSimplePw) {
		log.Warning(fmt.Sprintf("Bind Error: User %s login failed", userName))
		return ldap.LDAPResultInvalidCredentials, nil
	}

	id := connID(conn)
	o.lock.Lock()
	o.sessions[id] = ownCloudSession{
		user:        userName,
		password:    bindSimplePw,
		baseUrl:     o.cfg.Backend.Servers[0],
		useGraphAPI: o.cfg.Backend.UseGraphAPI,
	}
	o.lock.Unlock()

	stats.Frontend.Add("bind_successes", 1)
	log.Debug(fmt.Sprintf("Bind success as %s from %s", bindDN, conn.RemoteAddr().String()))
	return ldap.LDAPResultSuccess, nil
}

func (o ownCloudHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + o.cfg.Backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	log.Debug(fmt.Sprintf("Search request as %s from %s for %s on %s", bindDN, conn.RemoteAddr().String(), searchReq.Filter, searchBaseDN))
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN %s not in our BaseDN %s", bindDN, o.cfg.Backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, o.cfg.Backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, o.cfg.Backend.BaseDN)
	}
	// return all users in the config file - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	o.lock.Lock()
	id := connID(conn)
	session := o.sessions[id]
	o.lock.Unlock()

	switch filterEntity {
	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		groups, err := session.getGroups()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting groups")
		}
		for _, g := range groups {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*g.ID}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *g.ID)}})
			//			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.UnixID)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})
			if g.Members != nil {
				members := make([]string, len(g.Members))
				for i, v := range g.Members {
					members[i] = *v.ID
				}

				attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
			}
			dn := fmt.Sprintf("cn=%s,%s=groups,%s", *g.ID, o.cfg.Backend.GroupFormat, o.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "":
		userName := ""
		if searchBaseDN != strings.ToLower(o.cfg.Backend.BaseDN) {
			parts := strings.Split(strings.TrimSuffix(searchBaseDN, baseDN), ",")
			if len(parts) == 1 {
				userName = strings.TrimPrefix(parts[0], "cn=")
			}
		}
		users, err := session.getUsers(userName)
		if err != nil {
			log.Debug(err)
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting users")
		}
		for _, u := range users {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*u.ID}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{*u.ID}})
			if u.DisplayName != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{*u.DisplayName}})
			}
			if u.Mail != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{*u.Mail}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *u.ID)}})
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", o.cfg.Backend.NameFormat, *u.ID, o.cfg.Backend.GroupFormat, "users", o.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	stats.Frontend.Add("search_successes", 1)
	log.Debug(fmt.Sprintf("AP: Search OK: %s", searchReq.Filter))
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

func (o ownCloudHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	o.lock.Lock()
	defer o.lock.Unlock()
	delete(o.sessions, connID(conn))
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

func (o ownCloudHandler) login(name, pw string) bool {
	req, _ := http.NewRequest("GET", o.meUrl, nil)
	req.SetBasicAuth(name, pw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

type OCSGroupsResponse struct {
	Ocs struct {
		Meta struct {
			Message    interface{} `json:"message"`
			Statuscode int         `json:"statuscode"`
			Status     string      `json:"status"`
		} `json:"meta"`
		Data struct {
			Groups []string `json:"groups"`
		} `json:"data"`
	} `json:"ocs"`
}

func (o ownCloudSession) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(o.user, o.password)
	return http.DefaultTransport.RoundTrip(req)
}

func (o ownCloudSession) getGroups() ([]msgraph.Group, error) {
	if o.useGraphAPI {
		ctx := context.Background()
		req := o.NewClient().Groups().Request()
		req.Expand("members")
		return req.Get(ctx)
	}
	groupsUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/groups?format=json", o.baseUrl)

	req, _ := http.NewRequest("GET", groupsUrl, nil)
	req.SetBasicAuth(o.user, o.password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var f OCSGroupsResponse
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	ret := make([]msgraph.Group, len(f.Ocs.Data.Groups))
	for i, v := range f.Ocs.Data.Groups {
		ret[i] = msgraph.Group{DirectoryObject: msgraph.DirectoryObject{Entity: msgraph.Entity{ID: &v}}}
	}

	return ret, nil
}

type OCSUsersResponse struct {
	Ocs struct {
		Data struct {
			Users []string `json:"users"`
		} `json:"data"`
		Meta struct {
			Statuscode int         `json:"statuscode"`
			Message    interface{} `json:"message"`
			Status     string      `json:"status"`
		} `json:"meta"`
	} `json:"ocs"`
}

// NewClient returns GraphService request builder with default base URL
func (o ownCloudSession) NewClient() *msgraph.GraphServiceRequestBuilder {
	graphAPIBaseUrl := fmt.Sprintf("%s/index.php/apps/graphapi/v1.0/", o.baseUrl)

	httpClient := &http.Client{
		Transport: o,
	}
	g := msgraph.NewClient(httpClient)
	g.SetURL(graphAPIBaseUrl)
	return g
}

func (o ownCloudSession) getUsers(userName string) ([]msgraph.User, error) {
	if o.useGraphAPI {
		ctx := context.Background()
		req := o.NewClient().Users()
		if len(userName) > 0 {
			u, err := req.ID(userName).Request().Get(ctx)
			if err != nil {
				return nil, err
			}
			return []msgraph.User{*u}, nil
		}
		return req.Request().Get(ctx)
	}
	usersUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/users?format=json", o.baseUrl)

	req, _ := http.NewRequest("GET", usersUrl, nil)
	req.SetBasicAuth(o.user, o.password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var f OCSUsersResponse
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	ret := make([]msgraph.User, len(f.Ocs.Data.Users))
	for i, v := range f.Ocs.Data.Users {
		ret[i] = msgraph.User{DirectoryObject: msgraph.DirectoryObject{Entity: msgraph.Entity{ID: &v}}}
	}

	return ret, nil
}

func (o ownCloudSession) redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	log.Debug("Setting user and password")
	req.SetBasicAuth(o.user, o.password)
	return nil
}

func NewOwnCloudHandler(cfg *config.Config) Handler {
	meUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/user?format=json", cfg.Backend.Servers[0])

	handler := ownCloudHandler{cfg: cfg, meUrl: meUrl,
		sessions: make(map[string]ownCloudSession),
	}
	return handler
}
