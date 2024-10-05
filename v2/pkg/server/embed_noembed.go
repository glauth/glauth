//go:build !(embedsqlite || embedmysql)

package server

import (
	"errors"

	"github.com/glauth/glauth/v2/pkg/handler"
)

func NewEmbed(opts ...handler.Option) (handler.Handler, error) {
	return nil, errors.New("GLAuth was not built with support for an embedded plugin")
}
