package main

import (
	"expvar"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/GeertJohan/yubigo"
	"github.com/docopt/docopt-go"
	"github.com/nmcclain/ldap"
	"github.com/op/go-logging"
	"gopkg.in/amz.v1/aws"
	"gopkg.in/amz.v1/s3"
)

// Set with buildtime vars
var LastGitTag string
var BuildTime string
var GitCommit string
var GitClean string
var GitBranch string
var GitTagIsCommit string

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
	Database  string   // For Sql backend only
}
type configFrontend struct {
	AllowedBaseDNs []string // For LDAP backend only
	Listen         string
	Cert           string
	Key            string
	TLS            bool
}
type configLDAP struct {
	Enabled bool
	Listen  string
}
type configLDAPS struct {
	Enabled bool
	Listen  string
	Cert    string
	Key     string
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
	Name          string
	OtherGroups   []int
	PassSHA256    string
	PassAppSHA256 []string
	PrimaryGroup  int
	SSHKeys       []string
	OTPSecret     string
	Yubikey       string
	Disabled      bool
	UnixID        int
	Mail          string
	LoginShell    string
	GivenName     string
	SN            string
	Homedir       string
}
type configGroup struct {
	Name          string
	UnixID        int
	IncludeGroups []int
}
type config struct {
	API                configAPI
	Backend            configBackend
	Debug              bool
	YubikeyClientID    string
	YubikeySecret      string
	Frontend           configFrontend
	LDAP               configLDAP
	LDAPS              configLDAPS
	Groups             []configGroup
	Syslog             bool
	Users              []configUser
	ConfigFile         string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	AwsRegion          string
}

var log = logging.MustGetLogger(programName)

// Reads builtime vars and returns a full string containing info about
// the currently running version of the software. Primarily used by the
// --version flag at runtime.
func getVersionString() string {

	var versionstr string

	versionstr = "GLauth"

	// Notate the git context of the build
	switch {
	// If a release, use the tag
	case GitClean == "1" && GitTagIsCommit == "1":
		versionstr += " " + LastGitTag + "\n\n"

	// If this branch had a tag before, mention the branch and the tag to give a rough idea of the base version
	case len(GitBranch) > 1 && len(LastGitTag) > 1:
		versionstr += "\nNon-release build from branch " + GitBranch + ", based on tag " + LastGitTag + "\n\n"

	// If no previous tag specified, just mention the branch
	case len(GitBranch) > 1:
		versionstr += "\nNon-release build from branch " + GitBranch + "\n\n"

	// Fallback message, if all else fails
	default:
		versionstr += "\nNon-release build\n\n"
	}

	// Include build time
	if len(BuildTime) > 1 {
		versionstr += "Build time: " + BuildTime + "\n"
	}

	// Add commit hash
	if GitClean == "1" && len(GitCommit) > 1 {
		versionstr += "Commit: " + GitCommit + "\n"
	}

	return versionstr

}

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
	stats_general.Set("version", stringer(LastGitTag))

	// web API
	if cfg.API.Enabled {
		log.Debug("Web API enabled")
		go RunAPI(cfg)
	}

	yubiAuth := (*yubigo.YubiAuth)(nil)

	if len(cfg.YubikeyClientID) > 0 && len(cfg.YubikeySecret) > 0 {
		yubiAuth, err = yubigo.NewYubiAuth(cfg.YubikeyClientID, cfg.YubikeySecret)

		if err != nil {
			log.Fatalf("Yubikey Auth failed")
		}
	}

	// configure the backend
	s := ldap.NewServer()
	s.EnforceLDAP = true
	var handler Backend
	switch cfg.Backend.Datastore {
	case "ldap":
		handler = newLdapHandler(cfg)
	case "config":
		handler = newConfigHandler(newLocalToolbox(cfg), cfg, yubiAuth)
	case "sqlite":
		handler = newSqlHandler(newSqliteBackend(), newLocalToolbox(cfg), cfg, yubiAuth)
	case "mysql":
		handler = newSqlHandler(newMysqlBackend(), newLocalToolbox(cfg), cfg, yubiAuth)
	case "postgres":
		handler = newSqlHandler(newPostgresqlBackend(), newLocalToolbox(cfg), cfg, yubiAuth)
	default:
		log.Fatalf("Unsupported backend %s - must be 'config' or 'ldap' or 'sqlite'/'mysql'/'postgres'.", cfg.Backend.Datastore)
	}
	log.Notice(fmt.Sprintf("Using %s backend", cfg.Backend.Datastore))
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

	if cfg.LDAP.Enabled {
		// Dont block if also starting a LDAPS server afterwards
		shouldBlock := !cfg.LDAPS.Enabled

		if shouldBlock {
			startLDAP(&cfg.LDAP, s)
		} else {
			go startLDAP(&cfg.LDAP, s)
		}
	}

	if cfg.LDAPS.Enabled {
		// Always block here
		startLDAPS(&cfg.LDAPS, s)
	}

	log.Critical("AP exit")
}

func startLDAP(ldapConfig *configLDAP, server *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAP server listening on %s", ldapConfig.Listen))
	if err := server.ListenAndServe(ldapConfig.Listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

func startLDAPS(ldapsConfig *configLDAPS, server *ldap.Server) {
	log.Notice(fmt.Sprintf("LDAPS server listening on %s", ldapsConfig.Listen))
	if err := server.ListenAndServeTLS(ldapsConfig.Listen, ldapsConfig.Cert, ldapsConfig.Key); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

// doConfig reads the cli flags and config file
func doConfig() (*config, error) {
	cfg := config{}
	// setup defaults
	cfg.LDAP.Enabled = false
	cfg.LDAPS.Enabled = true

	// parse the command-line args
	args, err := docopt.Parse(usage, nil, true, getVersionString(), false)
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

	if len(cfg.Frontend.Listen) > 0 && (len(cfg.LDAP.Listen) > 0 || len(cfg.LDAPS.Listen) > 0) {
		// Both old server-config and new - dont allow
		return &cfg, fmt.Errorf("Both old and new server-config in use - please remove old format ([frontend]) and migrate to new format ([ldap], [ldaps])")
	}

	if len(cfg.Frontend.Listen) > 0 {
		// We're going with old format - parse it into new
		log.Warning("Config [frontend] is deprecated - please move to [ldap] and [ldaps] as-per documentation")

		cfg.LDAP.Enabled = !cfg.Frontend.TLS
		cfg.LDAPS.Enabled = cfg.Frontend.TLS

		if cfg.Frontend.TLS {
			cfg.LDAPS.Listen = cfg.Frontend.Listen
		} else {
			cfg.LDAP.Listen = cfg.Frontend.Listen
		}

		if len(cfg.Frontend.Cert) > 0 {
			cfg.LDAPS.Cert = cfg.Frontend.Cert
		}
		if len(cfg.Frontend.Key) > 0 {
			cfg.LDAPS.Key = cfg.Frontend.Key
		}
	}

	if !cfg.LDAP.Enabled && !cfg.LDAPS.Enabled {
		return &cfg, fmt.Errorf("No server configuration found: please provide either LDAP or LDAPS configuration")
	}

	if cfg.LDAPS.Enabled {
		// LDAPS enabled - verify requirements (cert, key, listen)
		if len(cfg.LDAPS.Cert) == 0 || len(cfg.LDAPS.Key) == 0 {
			return &cfg, fmt.Errorf("LDAPS was enabled but no certificate or key were specified: please disable LDAPS or use the 'cert' and 'key' options")
		}

		if len(cfg.LDAPS.Listen) == 0 {
			return &cfg, fmt.Errorf("No LDAPS bind address was specified: please disable LDAPS or use the 'listen' option")
		}
	}

	if cfg.LDAP.Enabled {
		// LDAP enabled - verify listen
		if len(cfg.LDAP.Listen) == 0 {
			return &cfg, fmt.Errorf("No LDAP bind address was specified: please disable LDAP or use the 'listen' option")
		}
	}

	switch cfg.Backend.Datastore {
	case "":
		cfg.Backend.Datastore = "config"
	case "config":
	case "ldap":
	case "sqlite":
	case "mysql":
	case "postgres":
	default:
		return &cfg, fmt.Errorf("Invalid backend %s - must be 'config' or 'ldap' or 'sqlite'/'mysql'/'postgres'.", cfg.Backend.Datastore)
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
