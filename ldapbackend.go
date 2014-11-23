package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/kr/pretty"
	"github.com/nmcclain/ldap"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ldapHandler struct {
	sessions map[string]ldapSession
	servers  []ldapBackend
	lock     sync.Mutex // for sessions and servers
	doPing   chan bool
	cfg      *config
}

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

func newLdapHandler(cfg *config) Backend {
	handler := ldapHandler{ // set non-zero-value defaults here
		sessions: make(map[string]ldapSession),
		doPing:   make(chan bool),
		cfg:      cfg,
	}
	// parse LDAP URLs
	for _, ldapurl := range cfg.Backend.Servers {
		l, err := parseURL(ldapurl)
		if err != nil {
			log.Fatal(err)
		}
		handler.servers = append(handler.servers, l)
	}

	// test server connectivity before listening, then keep it updated
	handler.monitorServers()

	return handler
}

//
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldap.LDAPResultCode, err error) {
	log.Debug("Bind request as %s from %s", bindDN, conn.RemoteAddr().String())
	stats_frontend.Add("bind_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats_frontend.Add("bind_ldapSession_errors", 1)
		log.Debug("Bind ops error as %s from %s == %s", bindDN, conn.RemoteAddr().String(), err.Error())
		return ldap.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		stats_frontend.Add("bind_errors", 1)
		log.Debug("Bind invalid creds as %s from %s", bindDN, conn.RemoteAddr().String())
		return ldap.LDAPResultInvalidCredentials, nil
	}
	stats_frontend.Add("bind_successes", 1)
	log.Debug("Bind success as %s from %s", bindDN, conn.RemoteAddr().String())
	return ldap.LDAPResultSuccess, nil
}

//
func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	log.Debug("Search request as %s from %s for %s", boundDN, conn.RemoteAddr().String(), searchReq.Filter)
	stats_frontend.Add("search_reqs", 1)
	s, err := h.getSession(conn)
	if err != nil {
		stats_frontend.Add("search_ldapSession_errors", 1)
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

	log.Debug("Search req to backend: %# v", pretty.Formatter(search))
	sr, err := s.ldap.Search(search)
	log.Debug("Backend Search result: %# v", pretty.Formatter(sr))
	ssr := ldap.ServerSearchResult{
		Entries:   sr.Entries,
		Referrals: sr.Referrals,
		Controls:  sr.Controls,
	}
	log.Debug("Frontend Search result: %# v", pretty.Formatter(ssr))
	if err != nil {
		e := err.(*ldap.Error)
		log.Debug("Search Err: %# v", pretty.Formatter(err))
		stats_frontend.Add("search_errors", 1)
		ssr.ResultCode = ldap.LDAPResultCode(e.ResultCode)
		return ssr, err
	}
	stats_frontend.Add("search_successes", 1)
	log.Debug("AP: Search OK: %s -> num of entries = %d\n", search.Filter, len(ssr.Entries))
	return ssr, nil
}
func (h ldapHandler) Close(boundDn string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	stats_frontend.Add("closes", 1)
	stats_backend.Add("closes", 1)
	return nil
}

// monitorServers tests server connectivity before listening, then keeps it updated
func (h *ldapHandler) monitorServers() {
	err := h.ping()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			select {
			case <-h.doPing:
				log.Notice("doPing requested due to server failure")
				err = h.ping()
				if err != nil {
					log.Fatal(err)
				}
			case <-time.NewTimer(60 * time.Second).C:
				log.Debug("doPing after timeout")
				err = h.ping()
				if err != nil {
					log.Fatal(err)
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
			log.Error(fmt.Sprintf("Server %s:%d ping failed: %s", s.Hostname, s.Port, err.Error()))
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
	log.Debug("Server health: %# v", pretty.Formatter(h.servers))
	b, err := json.Marshal(h.servers)
	if err != nil {
		log.Error(fmt.Sprintf("Error encoding tail data: %s", err.Error()))
	}
	stats_backend.Set("servers", stringer(string(b)))
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
	log.Debug("Best server: %# v", pretty.Formatter(favorite))
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
