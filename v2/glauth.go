package main

import (
	"bytes"
	"fmt"
	"github.com/GeertJohan/yubigo"
	"github.com/arl/statsviz"
	docopt "github.com/docopt/docopt-go"
	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/frontend"
	"github.com/glauth/glauth/v2/pkg/logging"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/hydronica/toml"
	"github.com/jinzhu/copier"
	"github.com/rs/zerolog"
	"gopkg.in/amz.v3/aws"
	"gopkg.in/amz.v3/s3"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
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
	if err := doConfig(checkConfig); err != nil {
		fmt.Println("Configuration file error")
		fmt.Println(err)
		os.Exit(1)
	}
	if checkConfig {
		fmt.Println("Config file seems ok (but I am not checking much at this time)")
		return
	}
	log.Info().Msg("AP start")

	startService()
}

func startService() {
	// stats
	stats.General.Set("version", stats.Stringer(LastGitTag))

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

	startConfigWatcher()

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
	)
	if err != nil {
		log.Error().Err(err).Msg("could not create server")
		os.Exit(1)
	}

	if activeConfig.LDAP.Enabled {
		// Don't block if also starting a LDAPS server afterwards
		shouldBlock := !activeConfig.LDAPS.Enabled

		if shouldBlock {
			if err := s.ListenAndServe(); err != nil {
				log.Error().Err(err).Msg("could not start LDAP server")
				os.Exit(1)
			}
		} else {
			go func() {
				if err := s.ListenAndServe(); err != nil {
					log.Error().Err(err).Msg("could not start LDAP server")
					os.Exit(1)
				}
			}()
		}
	}

	if activeConfig.LDAPS.Enabled {
		// Always block here
		if err := s.ListenAndServeTLS(); err != nil {
			log.Error().Err(err).Msg("could not start LDAPS server")
			os.Exit(1)
		}
	}

	log.Info().Msg("AP exit")
	os.Exit(1)
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
					if err := doConfig(false); err != nil {
						log.Info().Err(err).Msg("Could not reload config. Holding on to old config")
					} else {
						log.Info().Msg("Config was reloaded")
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

	if args, err = docopt.Parse(usage, nil, true, getVersionString(), false); err != nil {
		return err
	}

	return nil
}

func getConfigLocation() string {
	return args["--config"].(string)
}

func parseConfigFile(configFileLocation string) (*config.Config, error) {
	cfg := config.Config{}
	// setup defaults
	cfg.LDAP.Enabled = false
	cfg.LDAPS.Enabled = true

	// parse the config file
	if strings.HasPrefix(configFileLocation, "s3://") {
		region, present := aws.Regions[args["-r"].(string)]
		if present == false {
			return &cfg, fmt.Errorf("invalid AWS region: %s", args["-r"])
		}
		if args["--aws_endpoint_url"] != nil {
			region = aws.Region{
				Name:       "User defined",
				S3Endpoint: args["--aws_endpoint_url"].(string),
			}
			present = true
		}
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
		s3url := strings.TrimPrefix(configFileLocation, "s3://")
		parts := strings.SplitN(s3url, "/", 2)
		if len(parts) != 2 {
			return &cfg, fmt.Errorf("invalid S3 URL: %s", s3url)
		}
		b, err := s3.New(auth, region).Bucket(parts[0])
		if err != nil {
			return &cfg, err
		}
		tomlData, err := b.Get(parts[1])
		if err != nil {
			return &cfg, err
		}
		if _, err := toml.Decode(string(tomlData), &cfg); err != nil {
			return &cfg, err
		}
	} else { // local config file
		fInfo, err := os.Stat(configFileLocation)
		if err != nil {
			return &cfg, fmt.Errorf("non-existent config path: %s", configFileLocation)
		}

		var md toml.MetaData

		if fInfo.IsDir() { // multiple files in a directory
			rawCfgStruct := make(map[string]interface{})

			// To keep things simple, we are not going to use the default values built in Cfg
			// so far (LDAP.Enabled, LDAPS.Enabled, etc) so do not forget to specify them!
			/*
				sourcebuf := new(bytes.Buffer)
				err = toml.NewEncoder(sourcebuf).Encode(cfg)
				if err != nil {
					return &cfg, err
				}
				var initialRawCfgStruct interface{}
				if err := toml.Unmarshal(sourcebuf.Bytes(), &initialRawCfgStruct); err != nil {
					return &cfg, err
				}
				if err = mergeConfigs(&rawCfgStruct, initialRawCfgStruct); err != nil {
					return &cfg, err
				}
			*/

			files, _ := os.ReadDir(configFileLocation)
			for _, f := range files {
				canonicalName := filepath.Join(configFileLocation, f.Name())

				bs, _ := os.ReadFile(canonicalName)
				var curRawCfgStruct interface{}
				if err := toml.Unmarshal(bs, &curRawCfgStruct); err != nil {
					return &cfg, err
				}
				if err = mergeConfigs(&rawCfgStruct, curRawCfgStruct); err != nil {
					return &cfg, err
				}
			}

			destbuf := new(bytes.Buffer)
			err = toml.NewEncoder(destbuf).Encode(rawCfgStruct)
			if err != nil {
				return &cfg, err
			}
			fmt.Println(destbuf.String())
			merged := config.Config{}
			if md, err = toml.Decode(destbuf.String(), &merged); err != nil {
				return &cfg, err
			}
			cfg = merged
		} else {
			md, err = toml.DecodeFile(configFileLocation, &cfg)
			if err != nil {
				return &cfg, err
			}
		}

		switch users := md.Mappings()["users"].(type) {
		case []map[string]interface{}:
			for _, mduser := range users {
				if mduser["customattributes"] != nil {
					for idx, cfguser := range cfg.Users {
						if cfguser.Name == mduser["name"].(string) {
							switch attributes := mduser["customattributes"].(type) {
							case []map[string]interface{}:
								cfg.Users[idx].CustomAttrs = attributes[0]
							case map[string]interface{}:
								cfg.Users[idx].CustomAttrs = attributes
							default:
								log.Info().Interface("attributes", attributes).Msg("Unknown attribute structure in config file")
							}
							break
						}
					}
				}
			}
		}

	}

	// Backward Compability
	if cfg.Backend.Datastore != "" {
		if cfg.Backends != nil {
			return &cfg, fmt.Errorf("you cannot specify both [Backend] and [[Backends]] directives in the same configuration ")
		} else {
			cfg.Backends = append(cfg.Backends, cfg.Backend)
		}
	}

	// Patch with default values where not specified
	for i := range cfg.Backends {
		if cfg.Backends[i].NameFormat == "" {
			cfg.Backends[i].NameFormat = "cn"
		}
		if cfg.Backends[i].GroupFormat == "" {
			cfg.Backends[i].GroupFormat = "ou"
		}
		if cfg.Backends[i].SSHKeyAttr == "" {
			cfg.Backends[i].SSHKeyAttr = "sshPublicKey"
		}
	}
	//

	return &cfg, nil
}

func mergeConfigs(config1 interface{}, config2 interface{}) error {
	var merger func(int, string, interface{}, interface{}) error
	merger = func(depth int, keyName string, cfg1 interface{}, cfg2 interface{}) error {
		//fmt.Println(strings.Repeat("    ", depth), "Handling element: ", keyName, " for: ", cfg2)
		switch element2 := cfg2.(type) {
		case map[string]interface{}:
			//fmt.Println(strings.Repeat("     ", depth), " - A map")
			element2, ok := cfg2.(map[string]interface{})
			if !ok {
				return fmt.Errorf("config source: %s is not a map", keyName)
			}
			element1, ok := cfg1.(*map[string]interface{})
			if !ok {
				return fmt.Errorf("config dest: %s is not a map", keyName)
			}
			for k, _ := range element2 {
				//fmt.Println(strings.Repeat("     ", depth), "  - key: ", k)
				_, ok := (*element1)[k]
				if !ok {
					(*element1)[k] = element2[k]
				} else {
					//fmt.Println(strings.Repeat("     ", depth), "  - merging: ", element2[k])
					asanarrayptr, ok := (*element1)[k].([]map[string]interface{})
					if ok {
						if err := merger(depth+1, k, &asanarrayptr, element2[k]); err != nil {
							return err
						}
						(*element1)[k] = asanarrayptr
					} else {
						asamapptr, ok := (*element1)[k].(map[string]interface{})
						if ok {
							if err := merger(depth+1, k, &asamapptr, element2[k]); err != nil {
								return err
							}
							(*element1)[k] = asamapptr
						} else {
							return fmt.Errorf("config dest: %s does not make a valid map/array ptr", keyName)
						}
					}
				}
			}
		case []map[string]interface{}:
			//fmt.Println(strings.Repeat("     ", depth), " - An array")
			element2, ok := cfg2.([]map[string]interface{})
			if !ok {
				return fmt.Errorf("config source: %s is not a map array", keyName)
			}
			//fmt.Println(strings.Repeat("     ", depth), "  - element2: ", element2)
			element1, ok := cfg1.(*[]map[string]interface{})
			if !ok {
				return fmt.Errorf("config dest: %s is not a map array", keyName)
			}
			//fmt.Println(strings.Repeat("     ", depth), "  - element1: ", element1)
			for index, _ := range element2 {
				*element1 = append(*element1, element2[index])
			}
		case string:
			//fmt.Println(strings.Repeat("     ", depth), " - A string")
			element2, ok := cfg2.(string)
			if !ok {
				return fmt.Errorf("config: %s is not a string", keyName)
			}
		case bool:
			//fmt.Println(strings.Repeat("     ", depth), " - A boolean")
			element2, ok := cfg2.(bool)
			if !ok {
				return fmt.Errorf("config: %s is not a boolean value", keyName)
			}
		case float64:
			//fmt.Println(strings.Repeat("     ", depth), " - A float64")
			element2, ok := cfg2.(float64)
			if !ok {
				return fmt.Errorf("config: %s is not a float64 value", keyName)
			}
		case nil:
			//fmt.Println(strings.Repeat("     ", depth), " - Nil")
		default:
			log.Info().Str("type", reflect.TypeOf(element2).String()).Msg("Unknown element type found in configuration file. Ignoring.")
		}
		return nil
	}

	err := merger(0, "TOP", config1, config2)
	if err != nil {
		return err
	}
	return nil
}

func mergeConfigsO(config1 interface{}, config2 interface{}) (interface{}, error) {
	var merger func(int, string, interface{}, interface{}) (interface{}, error)
	merger = func(depth int, keyName string, cfg1 interface{}, cfg2 interface{}) (interface{}, error) {
		var returnElement interface{}
		fmt.Println(strings.Repeat("    ", depth), "Handling element: ", keyName, " for: ", cfg1)
		switch element1 := cfg1.(type) {
		case map[string]interface{}:
			element2, ok := cfg2.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("config: %s is not a map", keyName)
			}
			for k, value2 := range element2 {
				value1, ok := element1[k]
				if !ok {
					return nil, fmt.Errorf("config: %s not found in at least one config file", k)
				}
				merged, err := merger(depth+1, k, value1, value2)
				if err != nil {
					return merged, err
				}
				element1[k] = merged
			}
			returnElement = element1
		case string:
			element2, ok := cfg2.(string)
			if !ok {
				return nil, fmt.Errorf("config: %s is not a string", keyName)
			}
			if element2 != "" {
				element1 = element2
			}
			returnElement = element1
		case bool:
			element2, ok := cfg2.(bool)
			if !ok {
				return nil, fmt.Errorf("config: %s is not a boolean value", keyName)
			}
			if element2 {
				element1 = true
			}
			returnElement = element1
		case float64:
			element2, ok := cfg2.(float64)
			if !ok {
				return nil, fmt.Errorf("config: %s is not a float64 value", keyName)
			}
			if element2 != 0 {
				element1 = element2
			}
			returnElement = element1
		case nil:
			if cfg2 == nil {
				returnElement = nil
			} else {
				element2, ok := cfg2.(map[string]interface{})
				if ok {
					returnElement = element2
				} else {
					element3, ok := cfg2.([]interface{})
					if ok {
						returnElement = element3
					} else {
						log.Info().Msg("Unexpected interface type for an assignment. Ignoring.")
						returnElement = element1
					}
				}
			}
		default:
			log.Info().Str("type", reflect.TypeOf(element1).String()).Msg("Unknown element type found in configuration file. Ignoring.")
			returnElement = element1
		}
		fmt.Println(strings.Repeat("    ", depth), "Done with element: ", keyName, " for: ", returnElement)
		return returnElement, nil
	}

	/*
		flattenedConfig1, _ := json.Marshal(config1)
		var jsonConfig1 interface{}
		//json.Unmarshal(flattenedConfig1, &jsonConfig1)
		d1 := json.NewDecoder(bytes.NewReader(flattenedConfig1))
		d1.UseNumber()
		if err := d1.Decode(&jsonConfig1); err != nil {
			return config1, err
		}

		flattenedConfig2, _ := json.Marshal(config2)
		var jsonConfig2 interface{}
		//json.Unmarshal(flattenedConfig2, &jsonConfig2)
		//spew.Dump(jsonConfig2)
		d2 := json.NewDecoder(bytes.NewReader(flattenedConfig2))
		d2.UseNumber()
		if err := d2.Decode(&jsonConfig2); err != nil {
			return config1, err
		}
	*/

	blocks, err := merger(0, "TOP", config1, config2)
	if err != nil {
		return config1, err
	}
	//
	//
	// TODO: return blocks... we will convert back to toml when we are done merging!

	//
	buf := new(bytes.Buffer)
	err = toml.NewEncoder(buf).Encode(blocks)
	if err != nil {
		return config1, err
	}
	fmt.Println(buf.String())
	merged := config.Config{}
	if _, err := toml.Decode(buf.String(), &merged); err != nil {
		return config1, err
	}
	return merged, nil
}

func handleArgs(cfg config.Config) (*config.Config, error) {
	// LDAP flags
	if ldap, ok := args["--ldap"].(string); ok && ldap != "" {
		cfg.LDAP.Enabled = true
		cfg.LDAP.Listen = ldap
	}

	// LDAPS flags
	if ldaps, ok := args["--ldaps"].(string); ok && ldaps != "" {
		cfg.LDAPS.Enabled = true
		cfg.LDAPS.Listen = ldaps
	}
	if ldapsCert, ok := args["--ldaps-cert"].(string); ok && ldapsCert != "" {
		cfg.LDAPS.Cert = ldapsCert
	}
	if ldapsKey, ok := args["--ldaps-key"].(string); ok && ldapsKey != "" {
		cfg.LDAPS.Key = ldapsKey
	}

	return &cfg, nil
}

func handleLegacyConfig(cfg config.Config) (*config.Config, error) {
	if len(cfg.Frontend.Listen) > 0 && (len(cfg.LDAP.Listen) > 0 || len(cfg.LDAPS.Listen) > 0) {
		// Both old server-config and new - dont allow
		return &cfg, fmt.Errorf("both old and new server-config in use - please remove old format ([frontend]) and migrate to new format ([ldap], [ldaps])")
	}

	if len(cfg.Frontend.Listen) > 0 {
		// We're going with old format - parse it into new
		log.Info().Msg("Config [frontend] is deprecated - please move to [ldap] and [ldaps] as-per documentation")

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
	return &cfg, nil
}
func validateConfig(cfg config.Config) (*config.Config, error) {

	if !cfg.LDAP.Enabled && !cfg.LDAPS.Enabled {
		return &cfg, fmt.Errorf("no server configuration found: please provide either LDAP or LDAPS configuration")
	}

	if cfg.LDAPS.Enabled {
		// LDAPS enabled - verify requirements (cert, key, listen)
		if len(cfg.LDAPS.Cert) == 0 || len(cfg.LDAPS.Key) == 0 {
			return &cfg, fmt.Errorf("LDAPS was enabled but no certificate or key were specified: please disable LDAPS or use the 'cert' and 'key' options")
		}

		if len(cfg.LDAPS.Listen) == 0 {
			return &cfg, fmt.Errorf("no LDAPS bind address was specified: please disable LDAPS or use the 'listen' option")
		}
	}

	if cfg.LDAP.Enabled {
		// LDAP enabled - verify listen
		if len(cfg.LDAP.Listen) == 0 {
			return &cfg, fmt.Errorf("no LDAP bind address was specified: please disable LDAP or use the 'listen' option")
		}
	}

	//spew.Dump(cfg)
	for i := range cfg.Backends {
		switch cfg.Backends[i].Datastore {
		case "":
			cfg.Backends[i].Datastore = "config"
		case "config":
		case "ldap":
		case "owncloud":
		case "plugin":
		default:
			return &cfg, fmt.Errorf("invalid backend %s - must be 'config', 'ldap', 'owncloud' or 'plugin'", cfg.Backends[i].Datastore)
		}
	}

	// TODO: remove after deprecating UnixID on User and Group
	for _, user := range cfg.Users {
		if user.UnixID != 0 {
			user.UIDNumber = user.UnixID
			log.Info().Msg(fmt.Sprintf("User '%s': 'unixid' is deprecated - please move to 'uidnumber' as per documentation", user.Name))
		}
	}
	for _, group := range cfg.Groups {
		if group.UnixID != 0 {
			group.GIDNumber = group.UnixID
			log.Info().Msg(fmt.Sprintf("Group '%s': 'unixid' is deprecated - please move to 'gidnumber' as per documentation", group.Name))
		}
	}

	return &cfg, nil
}

// doConfig reads the cli flags and config file
func doConfig(checkConfig bool) error {
	// Parse config-file into config{} struct
	cfg, err := parseConfigFile(getConfigLocation())
	if err != nil {
		return err
	}

	// Handle parsed flags
	cfg, err = handleArgs(*cfg)
	if err != nil {
		return err
	}

	// Handle parsing of legacy [frontend] section into [ldap] and/or [ldaps] sections
	cfg, err = handleLegacyConfig(*cfg)
	if err != nil {
		return err
	}

	cfg, err = validateConfig(*cfg)
	if err != nil {
		return err
	}

	// Before greenlighting new config entirely, lets make sure the yubiauth works - in case they changed
	if activeConfig.YubikeyClientID != cfg.YubikeyClientID || activeConfig.YubikeySecret != cfg.YubikeySecret {
		if len(cfg.YubikeyClientID) > 0 && len(cfg.YubikeySecret) > 0 {
			_yubiAuth, err := yubigo.NewYubiAuth(cfg.YubikeyClientID, cfg.YubikeySecret)
			if err != nil {
				return err
			}

			// No errors, override
			yubiAuth = _yubiAuth
		}
	}

	// All config is validated and alright, copy to activeConfig
	if err := copier.Copy(activeConfig, cfg); err != nil {
		return err
	}

	// Handle logging settings for new config
	// - we do this last to make sure we only respect a fully validated config
	log = logging.InitLogging(activeConfig.Debug, activeConfig.Syslog, activeConfig.StructuredLog)

	if !checkConfig {
		if activeConfig.Debug {
			log.Info().Msg("Debugging enabled")
		}
		if activeConfig.Syslog {
			log.Info().Msg("Syslog enabled")
		}
	}

	return nil
}
