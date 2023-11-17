package toml

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/rs/zerolog/log"
	"gopkg.in/amz.v3/aws"
	"gopkg.in/amz.v3/s3"
)

type Config struct {
	Users []toml.Primitive
}

type User struct {
	Name             string
	CustomAttributes []toml.Primitive
}

// NewConfig reads the cli flags and config file
func NewConfig(checkConfig bool, location string, args map[string]interface{}) (*config.Config, error) {
	// Parse config-file into config{} struct
	cfg, err := parseConfigFile(location, args)
	if err != nil {
		return nil, err
	}

	// Handle parsed flags
	cfg, err = handleArgs(cfg, args)
	if err != nil {
		return nil, err
	}

	// Handle parsing of legacy [frontend] section into [ldap] and/or [ldaps] sections
	cfg, err = handleLegacyConfig(cfg)
	if err != nil {
		return nil, err
	}

	cfg, err = validateConfig(cfg)
	if err != nil {
		return nil, err
	}

	// TODO @shipperizer reinstate this
	// // Before greenlighting new config entirely, lets make sure the yubiauth works - in case they changed

	if _, err := yubigo.NewYubiAuth(cfg.YubikeyClientID, cfg.YubikeySecret); err != nil && len(cfg.YubikeyClientID) > 0 && len(cfg.YubikeySecret) > 0 {
		return nil, err
	}

	return cfg, nil
}

func parseConfigFile(configFileLocation string, args map[string]interface{}) (*config.Config, error) {
	cfg := new(config.Config)
	// setup defaults
	cfg.LDAP.Enabled = false
	cfg.LDAPS.Enabled = true

	// parse the config file
	if strings.HasPrefix(configFileLocation, "s3://") {
		region, present := aws.Regions[args["-r"].(string)]
		if !present {
			return cfg, fmt.Errorf("invalid AWS region: %s", args["-r"])
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
				return cfg, fmt.Errorf("AWS credentials not found: must use -K and -S flags, or set these env vars:\n\texport AWS_ACCESS_KEY_ID=\"AAA...\"\n\texport AWS_SECRET_ACCESS_KEY=\"BBBB...\"\n")
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
			return cfg, fmt.Errorf("invalid S3 URL: %s", s3url)
		}
		b, err := s3.New(auth, region).Bucket(parts[0])
		if err != nil {
			return cfg, err
		}
		tomlData, err := b.Get(parts[1])
		if err != nil {
			return cfg, err
		}
		if _, err := toml.Decode(string(tomlData), cfg); err != nil {
			return cfg, err
		}
	} else { // local config file
		fInfo, err := os.Stat(configFileLocation)
		if err != nil {
			return cfg, fmt.Errorf("non-existent config path: %s", configFileLocation)
		}

		if fInfo.IsDir() { // multiple files in a directory
			rawCfgStruct := make(map[string]interface{})

			// To keep things simple, we are not going to use the default values built in Cfg
			// so far (LDAP.Enabled, LDAPS.Enabled, etc) so do not forget to specify them!
			/*
				sourcebuf := new(bytes.Buffer)
				err = toml.NewEncoder(sourcebuf).Encode(cfg)
				if err != nil {
					return cfg, err
				}
				var initialRawCfgStruct interface{}
				if err := toml.Unmarshal(sourcebuf.Bytes(), &initialRawCfgStruct); err != nil {
					return cfg, err
				}
				if err = mergeConfigs(&rawCfgStruct, initialRawCfgStruct); err != nil {
					return cfg, err
				}
			*/

			files, _ := os.ReadDir(configFileLocation)
			for _, f := range files {
				canonicalName := filepath.Join(configFileLocation, f.Name())

				bs, _ := os.ReadFile(canonicalName)
				var curRawCfgStruct interface{}
				if err := toml.Unmarshal(bs, &curRawCfgStruct); err != nil {
					return cfg, err
				}
				if err = mergeConfigs(&rawCfgStruct, curRawCfgStruct); err != nil {
					return cfg, err
				}
			}

			destbuf := new(bytes.Buffer)
			err = toml.NewEncoder(destbuf).Encode(rawCfgStruct)
			if err != nil {
				return cfg, err
			}
			fmt.Println(destbuf.String())
			merged := config.Config{}
			if _, err = toml.Decode(destbuf.String(), &merged); err != nil {
				return cfg, err
			}
			cfg = &merged
		} else {
			_, err = toml.DecodeFile(configFileLocation, cfg)
			if err != nil {
				return cfg, err
			}
		}

		usersCustomAttributes(configFileLocation, cfg)
	}

	// Backward Compability
	if cfg.Backend.Datastore != "" {
		if cfg.Backends != nil {
			return cfg, fmt.Errorf("you cannot specify both [Backend] and [[Backends]] directives in the same configuration ")
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

	return cfg, nil
}

// usersCustomAttributes changes config passed in by adding extra information coming from the custom attributes
func usersCustomAttributes(location string, config *config.Config) {
	// TODO @shipperizer deal with multiple files like in line #126
	c := new(Config)

	md, err := toml.DecodeFile(location, c)

	if err != nil {
		log.Error().Err(err).Msg("issues parsing users...keep going")
		return
	}

	for _, u := range c.Users {
		user := new(User)
		md.PrimitiveDecode(u, user)

		if user.CustomAttributes == nil {
			continue
		}

		for idx, cUser := range config.Users {
			if cUser.Name != user.Name {
				continue
			}

			x := make(map[string]interface{})

			for _, attribute := range user.CustomAttributes {
				err := md.PrimitiveDecode(attribute, x)

				fmt.Println(err, x)

				for k, v := range x {

					if config.Users[idx].CustomAttrs == nil {
						config.Users[idx].CustomAttrs = make(map[string]interface{})
					}

					config.Users[idx].CustomAttrs[k] = v

				}
			}
		}
	}
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

func handleArgs(cfg *config.Config, args map[string]interface{}) (*config.Config, error) {
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

	return cfg, nil
}

func handleLegacyConfig(cfg *config.Config) (*config.Config, error) {
	if len(cfg.Frontend.Listen) > 0 && (len(cfg.LDAP.Listen) > 0 || len(cfg.LDAPS.Listen) > 0) {
		// Both old server-config and new - dont allow
		return cfg, fmt.Errorf("both old and new server-config in use - please remove old format ([frontend]) and migrate to new format ([ldap], [ldaps])")
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
	return cfg, nil
}
func validateConfig(cfg *config.Config) (*config.Config, error) {

	if !cfg.LDAP.Enabled && !cfg.LDAPS.Enabled {
		return cfg, fmt.Errorf("no server configuration found: please provide either LDAP or LDAPS configuration")
	}

	if cfg.LDAPS.Enabled {
		// LDAPS enabled - verify requirements (cert, key, listen)
		if len(cfg.LDAPS.Cert) == 0 || len(cfg.LDAPS.Key) == 0 {
			return cfg, fmt.Errorf("LDAPS was enabled but no certificate or key were specified: please disable LDAPS or use the 'cert' and 'key' options")
		}

		if len(cfg.LDAPS.Listen) == 0 {
			return cfg, fmt.Errorf("no LDAPS bind address was specified: please disable LDAPS or use the 'listen' option")
		}
	}

	if cfg.LDAP.Enabled {
		// LDAP enabled - verify listen
		if len(cfg.LDAP.Listen) == 0 {
			return cfg, fmt.Errorf("no LDAP bind address was specified: please disable LDAP or use the 'listen' option")
		}

		if cfg.LDAP.TLS && cfg.LDAP.TLSCert == "" && cfg.LDAP.TLSCertPath != "" {
			byteData, err := os.ReadFile(cfg.LDAP.TLSCertPath)
			cfg.LDAP.TLSCert = string(byteData)

			if err != nil {
				return cfg, fmt.Errorf("unable to read TLS certificate file")
			}
		}

		if cfg.LDAP.TLS && cfg.LDAP.TLSKey == "" && cfg.LDAP.TLSKeyPath != "" {
			byteData, err := os.ReadFile(cfg.LDAP.TLSKeyPath)
			cfg.LDAP.TLSKey = string(byteData)

			if err != nil {
				return cfg, fmt.Errorf("unable to read TLS key file")
			}
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
			return cfg, fmt.Errorf("invalid backend %s - must be 'config', 'ldap', 'owncloud' or 'plugin'", cfg.Backends[i].Datastore)
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

	return cfg, nil
}
