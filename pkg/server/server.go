package server

import (
	"errors"
	"fmt"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/pkg/backend"
	"github.com/glauth/glauth/pkg/config"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("glauth")

type ldapSvc struct {
	c        *config.Config
	yubiAuth *yubigo.YubiAuth
	l        *ldap.Server
}

func NewServer(cfg *config.Config) (*ldapSvc, error) {

	s := ldapSvc{
		c: cfg,
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
	var handler backend.Backend
	switch cfg.Backend.Datastore {
	case "ldap":
		handler = backend.NewLdapHandler(cfg)
	case "config":
		handler = backend.NewConfigHandler(cfg, s.yubiAuth)
	default:
		return nil, fmt.Errorf("unsupported backend %s - must be 'config' or 'ldap'", cfg.Backend.Datastore)
	}
	log.Notice(fmt.Sprintf("Using %s backend", cfg.Backend.Datastore))
	s.l.BindFunc("", handler)
	s.l.SearchFunc("", handler)
	s.l.CloseFunc("", handler)

	return &s, nil
}

func (s *ldapSvc) ListenAndServe() {

	if s.c.LDAP.Enabled {
		// Dont block if also starting a LDAPS server afterwards
		shouldBlock := !s.c.LDAPS.Enabled

		if shouldBlock {
			startLDAP(&s.c.LDAP, s.l)
		} else {
			go startLDAP(&s.c.LDAP, s.l)
		}
	}

	if s.c.LDAPS.Enabled {
		// Always block here
		startLDAPS(&s.c.LDAPS, s.l)
	}
}

func startLDAP(ldapConfig *config.LDAP, l *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAP server listening on %s", ldapConfig.Listen))
	if err := l.ListenAndServe(ldapConfig.Listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

func startLDAPS(ldapsConfig *config.LDAPS, l *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAPS server listening on %s", ldapsConfig.Listen))
	if err := l.ListenAndServeTLS(ldapsConfig.Listen, ldapsConfig.Cert, ldapsConfig.Key); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}
