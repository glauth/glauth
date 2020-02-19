package backend

import (
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("glauth")

// interface for backend handler
type Backend interface {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
}
