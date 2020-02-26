package server

import (
	"errors"
	"fmt"
	"os"

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
	default:
		return nil, fmt.Errorf("unsupported backend %s - must be 'config' or 'ldap'", s.c.Backend.Datastore)
	}
	s.log.V(3).Info("Using backend", "datastore", s.c.Backend.Datastore)
	s.l.BindFunc("", h)
	s.l.SearchFunc("", h)
	s.l.CloseFunc("", h)

	return &s, nil
}

func (s *LdapSvc) ListenAndServe() {

	if s.c.LDAP.Enabled {
		// Dont block if also starting a LDAPS server afterwards
		shouldBlock := !s.c.LDAPS.Enabled

		if shouldBlock {
			s.startLDAP()
		} else {
			go s.startLDAP()
		}
	}

	if s.c.LDAPS.Enabled {
		// Always block here
		s.startLDAPS()
	}
}

func (s *LdapSvc) startLDAP() {
	s.log.V(3).Info("LDAP server listening", "address", s.c.LDAP.Listen)
	if err := s.l.ListenAndServe(s.c.LDAP.Listen); err != nil {
		s.log.Error(err, "LDAP Server Failed")
		os.Exit(1)
		// TODO return error
	}
}

func (s *LdapSvc) startLDAPS() {
	s.log.V(3).Info("LDAPS server listening", "address", s.c.LDAPS.Listen)
	if err := s.l.ListenAndServeTLS(s.c.LDAPS.Listen, s.c.LDAPS.Cert, s.c.LDAPS.Key); err != nil {
		s.log.Error(err, "LDAP Server Failed")
		os.Exit(1)
		// TODO return error
	}
}
