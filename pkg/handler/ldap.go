package handler

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/stats"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
)

type ldapHandler struct {
	doPing   chan bool
	log      logr.Logger
	cfg      *config.Config
	lock     *sync.Mutex // for sessions and servers
	sessions map[string]ldapSession
	servers  []ldapBackend
}

// global lock for ldapHandler sessions & servers manipulation
var ldaplock sync.Mutex

type ldapSession struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
}
type ldapBackendStatus int

const (
	Down ldapBackendStatus = iota
	Up
)

type ldapBackend struct {
	Scheme   string
	Hostname string
	Port     int
	Status   ldapBackendStatus
	Ping     time.Duration
}

func NewLdapHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	handler := ldapHandler{ // set non-zero-value defaults here
		sessions: make(map[string]ldapSession),
		doPing:   make(chan bool),
		log:      options.Logger,
		cfg:      options.Config,
		lock:     &ldaplock,
	}
	// parse LDAP URLs
	for _, ldapurl := range handler.cfg.Backend.Servers {
		l, err := parseURL(ldapurl)
		if err != nil {
			handler.log.Error(err, "could not parse url")
			os.Exit(1)
			// TODO log error and os exit
		}
		handler.servers = append(handler.servers, l)
	}

	// test server connectivity before listening, then keep it updated
	handler.monitorServers()

	return handler
}

//
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	h.log.V(6).Info("Bind request", "binddn", bindDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats.Frontend.Add("bind_ldapSession_errors", 1)
		h.log.V(6).Info("could not get session", "binddn", bindDN, "src", conn.RemoteAddr(), "error", err)
		return ldap.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		stats.Frontend.Add("bind_errors", 1)
		h.log.V(6).Info("invalid creds", "binddn", bindDN, "src", conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil
	}
	stats.Frontend.Add("bind_successes", 1)
	h.log.V(6).Info("bind success", "binddn", bindDN, "src", conn.RemoteAddr())
	return ldap.LDAPResultSuccess, nil
}

//
func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	h.log.V(6).Info("Search request", "binddn", boundDN, "src", conn.RemoteAddr(), "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats.Frontend.Add("search_ldapSession_errors", 1)
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
	}
	search := ldap.NewSearchRequest(
		searchReq.BaseDN,
		searchReq.Scope,
		searchReq.DerefAliases,
		searchReq.SizeLimit,
		searchReq.TimeLimit,
		searchReq.TypesOnly,
		searchReq.Filter,
		searchReq.Attributes,
		searchReq.Controls,
	)

	h.log.V(6).Info("Search request to backend", "request", search)
	sr, err := s.ldap.Search(search)
	h.log.V(6).Info("Backend Search result", "result", sr)
	ssr := ldap.ServerSearchResult{
		Entries:   sr.Entries,
		Referrals: sr.Referrals,
		Controls:  sr.Controls,
	}
	h.log.V(6).Info("Frontend Search result", "result", ssr)
	if err != nil {
		e := err.(*ldap.Error)
		h.log.V(6).Info("Search Err", "error", err)
		stats.Frontend.Add("search_errors", 1)
		ssr.ResultCode = ldap.LDAPResultCode(e.ResultCode)
		return ssr, err
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", search.Filter, "numentries", len(ssr.Entries))
	return ssr, nil
}
func (h ldapHandler) Close(boundDn string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

// monitorServers tests server connectivity before listening, then keeps it updated
func (h *ldapHandler) monitorServers() {
	err := h.ping()
	if err != nil {
		h.log.Error(err, "could not ping server")
		os.Exit(1)
		// TODO return error
	}
	go func() {
		for {
			select {
			case <-h.doPing:
				h.log.V(3).Info("doPing requested due to server failure")
				err = h.ping()
				if err != nil {
					h.log.Error(err, "could not ping server")
					os.Exit(1)
					// TODO return error
				}
			case <-time.NewTimer(60 * time.Second).C:
				h.log.V(6).Info("doPing after timeout")
				err = h.ping()
				if err != nil {
					h.log.Error(err, "could not ping server")
					os.Exit(1)
					// TODO return error
				}
			}
		}
	}()
}

//
func (h ldapHandler) getSession(conn net.Conn) (ldapSession, error) {
	id := connID(conn)
	h.lock.Lock()
	s, ok := h.sessions[id] // use server connection if it exists
	h.lock.Unlock()
	if !ok { // open a new server connection if not
		var l *ldap.Conn
		server, err := h.getBestServer() // pick the best server
		if err != nil {
			return ldapSession{}, err
		}
		dest := fmt.Sprintf("%s:%d", server.Hostname, server.Port)
		if server.Scheme == "ldaps" {
			tlsCfg := &tls.Config{}
			if h.cfg.Backend.Insecure {
				tlsCfg.InsecureSkipVerify = true
			}
			l, err = ldap.DialTLS("tcp", dest, tlsCfg)
		} else if server.Scheme == "ldap" {
			l, err = ldap.Dial("tcp", dest)
		}
		if err != nil {
			select {
			case h.doPing <- true: // non-blocking send
			default:
			}
			return ldapSession{}, err
		}
		s = ldapSession{id: id, c: conn, ldap: l}
		h.lock.Lock()
		h.sessions[s.id] = s
		h.lock.Unlock()
	}
	return s, nil
}

//
func (h ldapHandler) ping() error {
	healthy := false
	for k, s := range h.servers {
		var l *ldap.Conn
		var err error
		dest := fmt.Sprintf("%s:%d", s.Hostname, s.Port)
		start := time.Now()
		if h.servers[0].Scheme == "ldaps" {
			tlsCfg := &tls.Config{}
			if h.cfg.Backend.Insecure {
				tlsCfg.InsecureSkipVerify = true
			}
			l, err = ldap.DialTLS("tcp", dest, tlsCfg)
		} else if h.servers[0].Scheme == "ldap" {
			l, err = ldap.Dial("tcp", dest)
		}
		elapsed := time.Since(start)
		h.lock.Lock()
		if err != nil || l == nil {
			h.log.V(1).Info("Server ping failed", "hostname", s.Hostname, "port", s.Port, "error", err)
			h.servers[k].Ping = 0
			h.servers[k].Status = Down
		} else {
			healthy = true
			h.servers[k].Ping = elapsed
			h.servers[k].Status = Up
			l.Close() // prank caller
		}
		h.lock.Unlock()
	}
	h.log.V(6).Info("Server health", "servers", h.servers)
	b, err := json.Marshal(h.servers)
	if err != nil {
		h.log.V(1).Info("Error encoding tail data", "error", err)
	}
	stats.Backend.Set("servers", stats.Stringer(string(b)))
	if healthy == false {
		return fmt.Errorf("No healthy servers")
	}
	return nil
}

//
func (h ldapHandler) getBestServer() (ldapBackend, error) {
	favorite := ldapBackend{}
	forever, err := time.ParseDuration("30m")
	if err != nil {
		return ldapBackend{}, err
	}
	bestping := forever
	for _, s := range h.servers {
		if s.Status == Up && s.Ping < bestping {
			favorite = s
			bestping = s.Ping
		}
	}
	if bestping == forever {
		return ldapBackend{}, fmt.Errorf("No healthy servers found")
	}
	h.log.V(6).Info("Best server", "favorite", favorite)
	return favorite, nil
}

// helper functions
func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
func parseURL(ldapurl string) (ldapBackend, error) {
	u, err := url.Parse(ldapurl)
	if err != nil {
		return ldapBackend{}, err
	}
	var port int
	if u.Scheme == "ldaps" {
		port = 636
	} else if u.Scheme == "ldap" {
		port = 389
	} else {
		return ldapBackend{}, fmt.Errorf("Unknown LDAP scheme: %s", u.Scheme)
	}
	parts := strings.Split(u.Host, ":")
	hostname := parts[0]
	if len(parts) > 1 {
		port, err = strconv.Atoi(parts[1])
		if err != nil {
			return ldapBackend{}, err
		}
	}
	return ldapBackend{Scheme: u.Scheme, Hostname: hostname, Port: port}, nil
}
