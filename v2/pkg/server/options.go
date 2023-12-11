package server

import (
	"context"
	"crypto/tls"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/config"
)

// Option defines a single option function.
type Option func(o *Options)

// Options defines the available options for this package.
type Options struct {
	Logger  zerolog.Logger
	Config  *config.Config
	TLSConfig *tls.Config  
	Monitor monitoring.MonitorInterface
	Tracer  trace.Tracer
	Context context.Context
}

// newOptions initializes the available default options.
func newOptions(opts ...Option) Options {
	opt := Options{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// Logger provides a function to set the logger option.
func Logger(val zerolog.Logger) Option {
	return func(o *Options) {
		o.Logger = val
	}
}

// Config provides a function to set the config option.
func Config(val *config.Config) Option {
	return func(o *Options) {
		o.Config = val
	}
}

// Context provides a function to set the context option.
func Context(val context.Context) Option {
	return func(o *Options) {
		o.Context = val
	}
}

// TLSConfig provides a function to set the TLS config option.
func TLSConfig(val *tls.Config) Option {
	return func(o *Options) {
		o.TLSConfig = val
	}
}

// Monitor provides a function to set the monitor option.
func Monitor(val monitoring.MonitorInterface) Option {
	return func(o *Options) {
		o.Monitor = val
	}
}

// Tracer provides a function to set the tracer option.
func Tracer(val trace.Tracer) Option {
	return func(o *Options) {
		o.Tracer = val
	}
}
