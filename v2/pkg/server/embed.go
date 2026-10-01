//go:build embed

package server

import (
	"context"
	"errors"

	"github.com/glauth/glauth/v2/pkg/embed"
	"github.com/glauth/glauth/v2/pkg/handler"
)

func NewEmbed(ctx context.Context, opts ...handler.Option) (handler.Handler, error) {
	var (
		// Erase the type so we can dynamically check at runtime
		handlerFunc   any = embed.NewHandler
		ok            bool
		legacyHandler func(...handler.Option) handler.Handler
		newHandler    func(context.Context, ...handler.Option) handler.Handler
	)
	newHandler, ok = handlerFunc.(func(context.Context, ...handler.Option) handler.Handler)
	if ok {
		return newHandler(ctx, opts...), nil
	}
	legacyHandler, ok = handlerFunc.(func(...handler.Option) handler.Handler)
	if ok {
		return legacyHandler(opts...), nil
	}
	return nil, errors.New("GLAuth failed to load the embedded plugin")
}
