package handler

import "github.com/nmcclain/ldap"

// Handler is the common interface for all datastores
type Handler interface {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
}
