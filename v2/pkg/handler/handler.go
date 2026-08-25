package handler

import (
	"context"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldaps"
)

type HelperMaker interface {
	FindUser(ctx context.Context, userName string, searchByUPN bool) (bool, config.User, error)
	FindGroup(ctx context.Context, groupName string) (bool, config.Group, error)
}

// Handler is the common interface for all datastores
type Handler interface {
	// read support
	ldaps.Binder
	ldaps.Searcher
	ldaps.Closer

	// write support
	ldaps.Adder
	ldaps.Modifier // Note: modifying eg the uid or cn might change the dn because the hierarchy is determined by the backend
	ldaps.Deleter

	// helper
	HelperMaker
}

// TODO When I grow up, I want to handle pointers same as I would in C
// and not need a counter because I would not allocate statically
// but use idiomatic slicing instead
type HandlerWrapper struct {
	Handlers []Handler
	Count    *int
}
