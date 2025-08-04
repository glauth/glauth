package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GeertJohan/yubigo"
	"github.com/arl/statsviz"
	docopt "github.com/docopt/docopt-go"
	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/v2/internal/monitoring"
	_tls "github.com/glauth/glauth/v2/internal/tls"
	"github.com/glauth/glauth/v2/internal/toml"
	"github.com/glauth/glauth/v2/internal/tracing"
	"github.com/glauth/glauth/v2/internal/version"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/frontend"
	"github.com/glauth/glauth/v2/pkg/logging"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/jinzhu/copier"

	"github.com/rs/zerolog"
)

const programName = "glauth"

var usage = `glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3 url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  --aws_endpoint_url <url>  Custom S3 endpoint.
  --ldap <address>          Listen address for the LDAP server.
  --ldaps <address>         Listen address for the LDAPS server.
  --ldaps-cert <cert-file>  Path to cert file for the LDAPS server.
  --ldaps-key <key-file>    Path to key file for the LDAPS server.
  --check-config            Check configuration file and exit.
  -h, --help                Show this screen.
  --version                 Show version.
`

var (
	log      zerolog.Logger
	args     map[string]interface{}
	yubiAuth *yubigo.YubiAuth

	activeConfig = &config.Config{}
)

func main() {

	if err := parseArgs(); err != nil {
		fmt.Println("Could not parse command-line arguments")
		fmt.Println(err)
		os.Exit(1)
	}
	checkConfig := false
	if cc, ok := args["--check-config"]; ok {
		if cc == true {
			checkConfig = true
		}
	}

	cfg, err := toml.NewConfig(checkConfig, getConfigLocation(), args)

	if err != nil {
		fmt.Println("Configuration file error")
		fmt.Println(err)
		os.Exit(1)
	}

	if checkConfig {
		fmt.Println("Config file seems ok (but I am not checking much at this time)")
		return
	}

	if err := copier.Copy(activeConfig, cfg); err != nil {
		log.Info().Err(err).Msg("Could not save reloaded config. Holding on to old config")
	}

	log = logging.InitLogging(activeConfig.Debug, activeConfig.Syslog, activeConfig.StructuredLog)

	if !checkConfig {
		if cfg.Debug {
			log.Info().Msg("Debugging enabled")
		}
		if cfg.Syslog {
			log.Info().Msg("Syslog enabled")
		}
	}

	log.Info().Msg("AP start")

	startService()
}

func startService() {
	// stats
	stats.General.Set("version", stats.Stringer(version.Version))

	// web API
	if activeConfig.API.Enabled {
		log.Info().Msg("Web API enabled")

		if activeConfig.API.Internals {
			statsviz.Register(
				http.DefaultServeMux,
				statsviz.Root("/internals"),
				statsviz.SendFrequency(1000*time.Millisecond),
			)
		}

		go frontend.RunAPI(
			frontend.Logger(log),
			frontend.Config(&activeConfig.API),
		)
	}

	monitor := monitoring.NewMonitor(&log)
	tracer := tracing.NewTracer(
		tracing.NewConfig(
			activeConfig.Tracing.Enabled,
			activeConfig.Tracing.GRPCEndpoint,
			activeConfig.Tracing.HTTPEndpoint,
			&log,
		),
	)

	startConfigWatcher()

	var err error
	var starttlsConfig *tls.Config
	if c := activeConfig.LDAP; c.Enabled && c.TLS {
		// TODO check if tls params are string or bytes and change config accordingly
		starttlsConfig, err = _tls.MakeTLS([]byte(c.TLSCert), []byte(c.TLSKey), c.LegacyTLS)

		if err != nil {
			log.Warn().Err(err).Msg("unable to configure TLS for StartTLS: StartTLS won't be supported")
		}
	}

	var ldapstlsConfig *tls.Config
	if c := activeConfig.LDAPS; c.Enabled {
		// TODO check if tls params are string or bytes and change config accordingly
		ldapstlsConfig, err = _tls.MakeTLS([]byte(c.Cert), []byte(c.Key), c.LegacyTLS)

		if err != nil {
			log.Warn().Err(err).Msg("unable to configure TLS for LDAPS")
			os.Exit(1)
		}
	}

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
		server.StartTLSConfig(starttlsConfig),
		server.LDAPSTLSConfig(ldapstlsConfig),
		server.Monitor(monitor),
		server.Tracer(tracer),
	)

	if err != nil {
		log.Error().Err(err).Msg("could not create server")
		os.Exit(1)
	}

	if activeConfig.LDAP.Enabled {
		go func() {
			if err := s.ListenAndServe(); err != nil {
				log.Error().Err(err).Msg("could not start LDAP server")
				os.Exit(1)
			}
		}()
	}

	if activeConfig.LDAPS.Enabled {
		go func() {
			if err := s.ListenAndServeTLS(); err != nil {
				log.Error().Err(err).Msg("could not start LDAPS server")
				os.Exit(1)
			}
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until we receive our signal.
	<-c

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	s.Shutdown()

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Info().Msg("AP exit")
	os.Exit(0)
}

func startConfigWatcher() {
	configFileLocation := getConfigLocation()
	if !activeConfig.WatchConfig || strings.HasPrefix(configFileLocation, "s3://") {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error().Err(err).Msg("could not start config-watcher")
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	go func() {
		isChanged, isRemoved := false, false
		for {
			select {
			case event := <-watcher.Events:
				log.Info().Str("e", event.Op.String()).Msg("watcher got event")
				if event.Op&fsnotify.Write == fsnotify.Write {
					isChanged = true
				} else if event.Op&fsnotify.Remove == fsnotify.Remove { // vim edit file with rename/remove
					isChanged, isRemoved = true, true
				} else if event.Op&fsnotify.Create == fsnotify.Create { // only when watching a directory
					isChanged = true
				}
			case err := <-watcher.Errors:
				log.Error().Err(err).Msg("watcher error")
			case <-ticker.C:
				// wakeup, try finding removed config
			}
			if _, err := os.Stat(configFileLocation); !os.IsNotExist(err) && (isRemoved || isChanged) {
				if isRemoved {
					log.Info().Str("file", configFileLocation).Msg("rewatching config")
					watcher.Add(configFileLocation) // overwrite
					isChanged, isRemoved = true, false
				}
				if isChanged {

					cfg, err := toml.NewConfig(false, configFileLocation, args)

					if err != nil {
						log.Info().Err(err).Msg("Could not reload config. Holding on to old config")
					} else {
						log.Info().Msg("Config was reloaded")

						if err := copier.Copy(activeConfig, cfg); err != nil {
							log.Info().Err(err).Msg("Could not save reloaded config. Holding on to old config")
						}
					}
					isChanged = false
				}
			}
		}
	}()

	watcher.Add(configFileLocation)
}

func parseArgs() error {
	var err error

	if args, err = docopt.Parse(usage, nil, true, version.GetVersion(), false); err != nil {
		return err
	}

	return nil
}

func getConfigLocation() string {
	return args["--config"].(string)
}
