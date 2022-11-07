package stats

import (
	"expvar"
)

// exposed expvar variables
var (
	Frontend = expvar.NewMap("proxy_frontend")
	Backend  = expvar.NewMap("proxy_backend")
	General  = expvar.NewMap("proxy")
)
