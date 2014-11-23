package main

import (
	"expvar"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/docopt/docopt-go"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
	"launchpad.net/goamz/aws"
	"launchpad.net/goamz/s3"
	"os"
	"strings"
)

var version = "0.1"

const programName = "glauth"

var usage = `glauth: securely expose your LDAP for external auth

Usage:
  glauth [options] -c <file|s3url>
  glauth -h --help
  glauth --version

Options:
  -c, --config <file>       Config file.
  -K <aws_key_id>           AWS Key ID.
  -S <aws_secret_key>       AWS Secret Key.
  -r <aws_region>           AWS Region [default: us-east-1].
  -h, --help                Show this screen.
  --version                 Show version.
`

// exposed expvar variables
var stats_frontend = expvar.NewMap("proxy_frontend")
var stats_backend = expvar.NewMap("proxy_backend")
var stats_general = expvar.NewMap("proxy")

// interface for backend handler
type Backend interface {
	ldap.Binder
	ldap.Searcher
	ldap.Closer
}

// config file
type configBackend struct {
	BaseDN    string
	Datastore string
	Insecure  bool     // For LDAP backend only
	Servers   []string // For LDAP backend only
}
type configFrontend struct {
	AllowedBaseDNs []string // For LDAP backend only
	Cert           string
	Key            string
	Listen         string
	TLS            bool
}
type configAPI struct {
	Cert        string
	Enabled     bool
	Key         string
	Listen      string
	SecretToken string
	TLS         bool
}
type configUser struct {
	Name         string
	OtherGroups  []int
	PassSHA256   string
	PrimaryGroup int
	SSHKeys      []string
	UnixID       int
}
type configGroup struct {
	Name   string
	UnixID int
}
type config struct {
	API                configAPI
	Backend            configBackend
	Debug              bool
	Frontend           configFrontend
	Groups             []configGroup
	Syslog             bool
	Users              []configUser
	ConfigFile         string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	AwsRegion          string
}

var log = logging.MustGetLogger(programName)

func main() {
	stderr := initLogging()
	log.Debug("AP start")

	cfg, err := doConfig()
	if err != nil {
		log.Fatalf("Configuration file error: %s", err.Error())
	}
	if cfg.Syslog {
		enableSyslog(stderr)
	}

	// stats
	stats_general.Set("version", stringer(version))

	// web API
	if cfg.API.Enabled {
		log.Debug("Web API enabled")
		go RunAPI(cfg)
	}

	// configure the backend
	s := ldap.NewServer()
	s.EnforceLDAP = true
	var handler Backend
	switch cfg.Backend.Datastore {
	case "ldap":
		handler = newLdapHandler(cfg)
	case "config":
		handler = newConfigHandler(cfg)
	default:
		log.Fatalf("Unsupported backend %s - must be 'config' or 'ldap'.", cfg.Backend.Datastore)
	}
	log.Notice(fmt.Sprintf("Using %s backend", cfg.Backend.Datastore))
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

	// start the frontend server
	if cfg.Frontend.TLS {
		log.Notice(fmt.Sprintf("Frontend LDAPS server listening on %s", cfg.Frontend.Listen))
		if err := s.ListenAndServeTLS(cfg.Frontend.Listen, cfg.Frontend.Cert, cfg.Frontend.Key); err != nil {
			log.Fatalf("LDAP Server Failed: %s", err.Error())
		}
	} else {
		log.Notice(fmt.Sprintf("Frontend LDAP server listening on %s", cfg.Frontend.Listen))
		if err := s.ListenAndServe(cfg.Frontend.Listen); err != nil {
			log.Fatalf("LDAP Server Failed: %s", err.Error())
		}
	}
	log.Critical("AP exit")
}

// doConfig reads the cli flags and config file
func doConfig() (*config, error) {
	cfg := config{}
	// setup defaults
	cfg.Frontend.TLS = true

	// parse the command-line args
	args, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		return &cfg, err
	}

	// parse the config file
	if strings.HasPrefix(args["--config"].(string), "s3://") {
		if _, present := aws.Regions[args["-r"].(string)]; present == false {
			return &cfg, fmt.Errorf("Invalid AWS region: %s", args["-r"])
		}
		region := aws.Regions[args["-r"].(string)]
		auth, err := aws.EnvAuth()
		if err != nil {
			if args["-K"] == nil || args["-S"] == nil {
				return &cfg, fmt.Errorf("AWS credentials not found: must use -K and -S flags, or set these env vars:\n\texport AWS_ACCESS_KEY_ID=\"AAA...\"\n\texport AWS_SECRET_ACCESS_KEY=\"BBBB...\"\n")
			}
			auth = aws.Auth{
				AccessKey: args["-K"].(string),
				SecretKey: args["-S"].(string),
			}
		}
		// parse S3 url
		s3url := strings.TrimPrefix(args["--config"].(string), "s3://")
		parts := strings.SplitN(s3url, "/", 2)
		if len(parts) != 2 {
			return &cfg, fmt.Errorf("Invalid S3 URL: %s", s3url)
		}
		b := s3.New(auth, region).Bucket(parts[0])
		tomlData, err := b.Get(parts[1])
		if err != nil {
			return &cfg, err
		}
		if _, err := toml.Decode(string(tomlData), &cfg); err != nil {
			return &cfg, err
		}
	} else { // local config file
		if _, err := toml.DecodeFile(args["--config"].(string), &cfg); err != nil {
			return &cfg, err
		}
	}
	// enable features
	if cfg.Debug {
		logging.SetLevel(logging.DEBUG, programName)
		log.Debug("Debugging enabled")
	}
	switch cfg.Backend.Datastore {
	case "":
		cfg.Backend.Datastore = "config"
	case "config":
	case "ldap":
	default:
		return &cfg, fmt.Errorf("Invalid backend %s - must be 'config' or 'ldap'.", cfg.Backend.Datastore)
	}
	return &cfg, nil
}

// initLogging sets up logging to stderr
func initLogging() *logging.LogBackend {
	format := "%{color}%{time:15:04:05.000000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}"
	logBackend := logging.NewLogBackend(os.Stderr, "", 0)
	logging.SetBackend(logBackend)
	logging.SetLevel(logging.NOTICE, programName)
	logging.SetFormatter(logging.MustStringFormatter(format))
	return logBackend
}

// enableSyslog turns on syslog and turns off color
func enableSyslog(stderrBackend *logging.LogBackend) {
	format := "%{time:15:04:05.000000} %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}"
	logging.SetFormatter(logging.MustStringFormatter(format))
	syslogBackend, err := logging.NewSyslogBackend("")
	if err != nil {
		log.Fatal(err)
	}
	logging.SetBackend(stderrBackend, syslogBackend)
	log.Debug("Syslog enabled")
}
