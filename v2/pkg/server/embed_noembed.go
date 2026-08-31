//go:build !embed

package server

import (
	"context"
	"errors"

	"github.com/glauth/glauth/v2/pkg/handler"
)

func NewEmbed(ctx context.Context, opts ...handler.Option) (handler.Handler, error) {
	return nil, errors.New("GLAuth was not built with support for an embedded plugin")
}
