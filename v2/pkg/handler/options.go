package handler

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/config"
)

// Option defines a single option function.
type Option func(o *Options)

// Options defines the available options for this package.
type Options struct {
	Backend    config.Backend
	Handlers   HandlerWrapper
	Logger     *zerolog.Logger
	Config     *config.Config
	Context    *context.Context
	YubiAuth   *yubigo.YubiAuth
	Helper     Handler
	LDAPHelper LDAPOpsHelper
	Monitor    monitoring.MonitorInterface
}

// newOptions initializes the available default options.
func newOptions(opts ...Option) Options {
	opt := Options{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// NewOptions initializes the available default options.
func NewOptions(opts ...Option) Options {
	opt := Options{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// Backend is our current backend
func Backend(val config.Backend) Option {
	return func(o *Options) {
		o.Backend = val
	}
}

// Handlers Our friendly handlers for all backends
func Handlers(val HandlerWrapper) Option {
	return func(o *Options) {
		o.Handlers = val
	}
}

// Logger provides a function to set the logger option.
func Logger(val *zerolog.Logger) Option {
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
func Context(val *context.Context) Option {
	return func(o *Options) {
		o.Context = val
	}
}

// YubiAuth provides a function to set the yubiauth option.
func YubiAuth(val *yubigo.YubiAuth) Option {
	return func(o *Options) {
		o.YubiAuth = val
	}
}

// Helper If we specified a helper, for instance for OTP injection
func Helper(val Handler) Option {
	return func(o *Options) {
		o.Helper = val
	}
}

// LDAPHelper Global LDAP Handler
func LDAPHelper(val LDAPOpsHelper) Option {
	return func(o *Options) {
		o.LDAPHelper = val
	}
}

// Monitor provides a function to set the monitor option.
func Monitor(val monitoring.MonitorInterface) Option {
	return func(o *Options) {
		o.Monitor = val
	}
}
