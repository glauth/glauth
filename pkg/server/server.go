package server

import (
	"errors"
	"fmt"
	"plugin"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/handler"
	"github.com/go-logr/logr"
	"github.com/nmcclain/ldap"
)

type LdapSvc struct {
	log      logr.Logger
	c        *config.Config
	yubiAuth *yubigo.YubiAuth
	l        *ldap.Server
}

func NewServer(opts ...Option) (*LdapSvc, error) {
	options := newOptions(opts...)

	s := LdapSvc{
		log: options.Logger,
		c:   options.Config,
	}

	var err error

	if len(s.c.YubikeyClientID) > 0 && len(s.c.YubikeySecret) > 0 {
		s.yubiAuth, err = yubigo.NewYubiAuth(s.c.YubikeyClientID, s.c.YubikeySecret)

		if err != nil {
			return nil, errors.New("Yubikey Auth failed")
		}
	}

	// configure the backend
	s.l = ldap.NewServer()
	s.l.EnforceLDAP = true
	var h handler.Handler
	switch s.c.Backend.Datastore {
	case "ldap":
		h = handler.NewLdapHandler(
			handler.Logger(s.log),
			handler.Config(s.c),
		)
	case "owncloud":
		h = handler.NewOwnCloudHandler(
			handler.Logger(s.log),
			handler.Config(s.c),
		)
	case "config":
		h = handler.NewConfigHandler(
			handler.Logger(s.log),
			handler.Config(s.c),
			handler.YubiAuth(s.yubiAuth),
		)
	case "plugin":
		plug, err := plugin.Open(s.c.Backend.Plugin)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to load specified backend plugin: %s", err))
		}
		nph, err := plug.Lookup(s.c.Backend.PluginHandler)
		if err != nil {
			return nil, errors.New("Unable to find 'NewPluginHandler' in loaded backend plugin")
		}
		initFunc, ok := nph.(func(...handler.Option) handler.Handler)

		if !ok {
			return nil, errors.New("Loaded backend plugin lacks a proper NewPluginHandler function")
		}
		// Normally, here, we would somehow have imported our plugin into our
		// handler namespace. Oops?
		h = initFunc(
			handler.Logger(s.log),
			handler.Config(s.c),
			handler.YubiAuth(s.yubiAuth),
		)
	default:
		return nil, fmt.Errorf("unsupported backend %s - must be 'config', 'ldap' or 'owncloud'", s.c.Backend.Datastore)
	}
	s.log.V(3).Info("Using backend", "datastore", s.c.Backend.Datastore)
	s.l.BindFunc("", h)
	s.l.SearchFunc("", h)
	s.l.CloseFunc("", h)

	return &s, nil
}

// ListenAndServe listens on the TCP network address s.c.LDAP.Listen
func (s *LdapSvc) ListenAndServe() error {
	s.log.V(3).Info("LDAP server listening", "address", s.c.LDAP.Listen)
	return s.l.ListenAndServe(s.c.LDAP.Listen)
}

// ListenAndServeTLS listens on the TCP network address s.c.LDAPS.Listen
func (s *LdapSvc) ListenAndServeTLS() error {
	s.log.V(3).Info("LDAPS server listening", "address", s.c.LDAPS.Listen)
	return s.l.ListenAndServeTLS(
		s.c.LDAPS.Listen,
		s.c.LDAPS.Cert,
		s.c.LDAPS.Key,
	)
}

// Shutdown ends listeners by sending true to the ldap serves quit channel
func (s *LdapSvc) Shutdown() {
	s.l.Quit <- true
}
