package tracing

import (
	"github.com/rs/zerolog"
)

type Config struct {
	OtelHTTPEndpoint string
	OtelGRPCEndpoint string
	Logger           *zerolog.Logger

	Enabled bool
}

func NewConfig(enabled bool, otelGRPCEndpoint, otelHTTPEndpoint string, logger *zerolog.Logger) *Config {
	c := new(Config)

	c.OtelGRPCEndpoint = otelGRPCEndpoint
	c.OtelHTTPEndpoint = otelHTTPEndpoint
	c.Logger = logger
	c.Enabled = enabled

	return c
}
