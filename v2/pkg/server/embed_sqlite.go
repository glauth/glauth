//go:build embedsqlite

package server

import (
	"github.com/glauth/glauth/v2/pkg/embed"
	"github.com/glauth/glauth/v2/pkg/handler"
)

func NewEmbed(opts ...handler.Option) (handler.Handler, error) {
	return embed.NewSQLiteHandler(opts...), nil
}
