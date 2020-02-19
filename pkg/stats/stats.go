package stats

import "expvar"

// exposed expvar variables
var Frontend = expvar.NewMap("proxy_frontend")
var Backend = expvar.NewMap("proxy_backend")
var General = expvar.NewMap("proxy")
