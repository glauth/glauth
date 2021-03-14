package handler

import (
	"github.com/glauth/glauth/pkg/config"
	"github.com/nmcclain/ldap"
)

type HelperMaker interface {
	FindUser(userName string) (bool, config.User, error)
}

// Handler is the common interface for all datastores
type Handler interface {
	// read support
	ldap.Binder
	ldap.Searcher
	ldap.Closer

	// write support
	ldap.Adder
	ldap.Modifier // Note: modifying eg the uid or cn might change the dn because the hierarchy is determined by the backend
	ldap.Deleter

	// helper
	HelperMaker
}
