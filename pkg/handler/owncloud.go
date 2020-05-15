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
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
	msgraph "github.com/yaegashi/msgraph.go/v1.0"
)

type ownCloudSession struct {
	log         logr.Logger
	user        string
	password    string
	endpoint    string
	useGraphAPI bool
}
type ownCloudHandler struct {
	log      logr.Logger
	cfg      *config.Config
	meURL    string
	sessions map[string]ownCloudSession
	lock     sync.Mutex
}

func (h ownCloudHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
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
	if len(parts) > 2 {
		h.log.V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	userName := strings.TrimPrefix(parts[0], "cn=")

	// try to login
	if !h.login(userName, bindSimplePw) {
		h.log.V(2).Info("Login failed", "username", userName, "basedn", h.cfg.Backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	id := connID(conn)
	h.lock.Lock()
	h.sessions[id] = ownCloudSession{
		log:         h.log,
		user:        userName,
		password:    bindSimplePw,
		endpoint:    h.cfg.Backend.Servers[0],
		useGraphAPI: h.cfg.Backend.UseGraphAPI,
	}
	h.lock.Unlock()

	stats.Frontend.Add("bind_successes", 1)
	h.log.V(6).Info("Bind success", "binddn", bindDN, "basedn", h.cfg.Backend.BaseDN, "src", conn.RemoteAddr())
	return ldap.LDAPResultSuccess, nil
}

func (h ownCloudHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.cfg.Backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.V(6).Info("Search request", "binddn", bindDN, "basedn", baseDN, "src", conn.RemoteAddr(), "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN %s not in our BaseDN %s", bindDN, h.cfg.Backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.cfg.Backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.cfg.Backend.BaseDN)
	}
	// return all users in the config file - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	h.lock.Lock()
	id := connID(conn)
	session := h.sessions[id]
	h.lock.Unlock()

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
			dn := fmt.Sprintf("cn=%s,%s=groups,%s", *g.ID, h.cfg.Backend.GroupFormat, h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "":
		userName := ""
		if searchBaseDN != strings.ToLower(h.cfg.Backend.BaseDN) {
			parts := strings.Split(strings.TrimSuffix(searchBaseDN, baseDN), ",")
			if len(parts) >= 1 {
				userName = strings.TrimPrefix(parts[0], "cn=")
			}
		}
		users, err := session.getUsers(userName)
		if err != nil {
			h.log.V(6).Info("Could not get user", "username", userName, "err", err)
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
			dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.cfg.Backend.NameFormat, *u.ID, h.cfg.Backend.GroupFormat, "users", h.cfg.Backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", searchReq.Filter)
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not yet supported for the owncloud backend
func (h ownCloudHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the owncloud backend
func (h ownCloudHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the owncloud backend
func (h ownCloudHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h ownCloudHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

func (h ownCloudHandler) login(name, pw string) bool {
	req, _ := http.NewRequest("GET", h.meURL, nil)
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

func (s ownCloudSession) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(s.user, s.password)
	return http.DefaultTransport.RoundTrip(req)
}

func (s ownCloudSession) getGroups() ([]msgraph.Group, error) {
	if s.useGraphAPI {
		ctx := context.Background()
		req := s.NewClient().Groups().Request()
		req.Expand("members")
		return req.Get(ctx)
	}
	groupsUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/groups?format=json", s.endpoint)

	req, _ := http.NewRequest("GET", groupsUrl, nil)
	req.SetBasicAuth(s.user, s.password)
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
	for i := range f.Ocs.Data.Groups {
		ret[i] = msgraph.Group{DirectoryObject: msgraph.DirectoryObject{Entity: msgraph.Entity{ID: &f.Ocs.Data.Groups[i]}}}
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
func (s ownCloudSession) NewClient() *msgraph.GraphServiceRequestBuilder {
	httpClient := &http.Client{
		Transport: s,
	}
	g := msgraph.NewClient(httpClient)
	g.SetURL(s.endpoint)
	return g
}

func (s ownCloudSession) getUsers(userName string) ([]msgraph.User, error) {
	if s.useGraphAPI {
		ctx := context.Background()
		req := s.NewClient().Users()
		if len(userName) > 0 {
			u, err := req.ID(userName).Request().Get(ctx)
			if err != nil {
				return nil, err
			}
			return []msgraph.User{*u}, nil
		}
		return req.Request().Get(ctx)
	}
	usersUrl := fmt.Sprintf("%s/ocs/v2.php/cloud/users?format=json", s.endpoint)

	req, _ := http.NewRequest("GET", usersUrl, nil)
	req.SetBasicAuth(s.user, s.password)
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
	for i := range f.Ocs.Data.Users {
		ret[i] = msgraph.User{
			DirectoryObject: msgraph.DirectoryObject{
				Entity: msgraph.Entity{ID: &f.Ocs.Data.Users[i]},
			},
		}
	}

	return ret, nil
}

func (s ownCloudSession) redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	s.log.V(6).Info("Setting user and password", "username", s.user)
	req.SetBasicAuth(s.user, s.password)
	return nil
}

func NewOwnCloudHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	meURL := fmt.Sprintf("%s/ocs/v2.php/cloud/user?format=json", options.Config.Backend.Servers[0])

	handler := ownCloudHandler{
		log:      options.Logger,
		cfg:      options.Config,
		meURL:    meURL,
		sessions: make(map[string]ownCloudSession),
	}
	return handler
}
