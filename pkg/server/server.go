package server

import (
	"errors"
	"fmt"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/config"
	"github.com/glauth/glauth/pkg/handler"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
)

type LdapSvc struct {
	log      *logging.Logger
	c        *config.Config
	yubiAuth *yubigo.YubiAuth
	l        *ldap.Server
}

func NewServer(log *logging.Logger, cfg *config.Config) (*LdapSvc, error) {

	s := LdapSvc{
		log: log,
		c:   cfg,
	}

	var err error

	if len(cfg.YubikeyClientID) > 0 && len(cfg.YubikeySecret) > 0 {
		s.yubiAuth, err = yubigo.NewYubiAuth(cfg.YubikeyClientID, cfg.YubikeySecret)

		if err != nil {
			return nil, errors.New("Yubikey Auth failed")
		}
	}

	// configure the backend
	s.l = ldap.NewServer()
	s.l.EnforceLDAP = true
	var h handler.Handler
	switch cfg.Backend.Datastore {
	case "ldap":
		h = handler.NewLdapHandler(log, cfg)
	case "owncloud":
		h = handler.NewOwnCloudHandler(log, cfg)
	case "config":
		h = handler.NewConfigHandler(log, cfg, s.yubiAuth)
	default:
		return nil, fmt.Errorf("unsupported backend %s - must be 'config' or 'ldap'", cfg.Backend.Datastore)
	}
	log.Notice(fmt.Sprintf("Using %s backend", cfg.Backend.Datastore))
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
	s.log.Notice(fmt.Sprintf("LDAP server listening on %s", s.c.LDAP.Listen))
	if err := s.l.ListenAndServe(s.c.LDAP.Listen); err != nil {
		s.log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

func (s *LdapSvc) startLDAPS() {
	s.log.Notice(fmt.Sprintf("LDAPS server listening on %s", s.c.LDAPS.Listen))
	if err := s.l.ListenAndServeTLS(s.c.LDAPS.Listen, s.c.LDAPS.Cert, s.c.LDAPS.Key); err != nil {
		s.log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}
