package handler

import "github.com/nmcclain/ldap"

// interface for backend handler
type Handler interface {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
}
