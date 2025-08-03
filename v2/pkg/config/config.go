package config

import "time"

// config file
type (
	Backend struct {
		BaseDN                    string
		Datastore                 string
		Insecure                  bool     // For LDAP and owncloud backend only
		Servers                   []string // For LDAP and owncloud backend only
		NameFormat                string   // e.g. cn, ou, uid, or a comma separated list of them
		NameFormatAsArray         []string // we will explode NameFormat on commas
		GroupFormat               string   // e.g. cn, ou, gid, or a comma separated list of them
		GroupFormatAsArray        []string // we will explode GroupFormat on commas
		SSHKeyAttr                string
		UseGraphAPI               bool   // For ownCloud backend only
		Plugin                    string // Path to plugin library, for plugin backend only
		PluginHandler             string // Name of plugin's main handler function
		Database                  string // For Database backends only
		GroupWithSearchCapability string // For PamLinux backend only
		AnonymousDSE              bool   // For Config and Database backends only
	}

	Helper struct {
		Enabled       bool
		BaseDN        string
		Datastore     string
		Plugin        string // Path to plugin library, for plugin backend only
		PluginHandler string // Name of plugin's main handler function
		Database      string // For MySQL backend only TODO REname to match plugin
	}

	Frontend struct {
		AllowedBaseDNs []string // For LDAP backend only
		Listen         string
		Cert           string
		Key            string
		TLS            bool
	}

	LDAP struct {
		Enabled bool
		Listen  string
		// StartTLS parameters
		TLS         bool
		TLSCert     string
		TLSKey      string
		TLSCertPath string
		TLSKeyPath  string
		LegacyTLS   bool
	}

	LDAPS struct {
		Enabled bool
		Listen  string
		// LDAPS TLS parameters
		Cert      string
		Key       string
		CertPath  string
		KeyPath   string
		LegacyTLS bool
	}

	API struct {
		Cert        string
		Enabled     bool
		Internals   bool
		Key         string
		Listen      string
		SecretToken string
		TLS         bool
	}

	Behaviors struct {
		IgnoreCapabilities    bool
		LimitFailedBinds      bool
		NumberOfFailedBinds   int
		PeriodOfFailedBinds   time.Duration
		BlockFailedBindsFor   time.Duration
		PruneSourceTableEvery time.Duration
		PruneSourcesOlderThan time.Duration
		LegacyVersion         int
	}

	Capability struct {
		Action string
		Object string
	}

	// UserAuthenticator authenticates a user via custom auth from a backend
	UserAuthenticator func(user *User, pw string) error
	User              struct {
		Name          string
		OtherGroups   []int
		PassSHA256    string
		PassBcrypt    string
		PassAppSHA256 []string
		PassAppBcrypt []string
		PassAppCustom UserAuthenticator `toml:"-"`
		PrimaryGroup  int
		Capabilities  []Capability
		SSHKeys       []string
		OTPSecret     string
		Yubikey       string
		Disabled      bool
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		UIDNumber     int
		Mail          string
		LoginShell    string
		GivenName     string
		SN            string
		Homedir       string
		CustomAttrs   map[string]interface{}
	}

	Group struct {
		Name          string
		UnixID        int // TODO: remove after deprecating UnixID on User and Group
		GIDNumber     int
		Capabilities  []Capability
		IncludeGroups []int
	}

	Tracing struct {
		Enabled      bool
		GRPCEndpoint string
		HTTPEndpoint string
	}

	Config struct {
		API                API
		Backend            Backend // Deprecated
		Backends           []Backend
		Helper             Helper
		Behaviors          Behaviors
		Debug              bool
		Syslog             bool
		StructuredLog      bool
		WatchConfig        bool
		YubikeyClientID    string
		YubikeySecret      string
		Frontend           Frontend
		LDAP               LDAP
		LDAPS              LDAPS
		Groups             []Group
		Users              []User
		Tracing            Tracing
		ConfigFile         string
		AwsAccessKeyId     string
		AwsSecretAccessKey string
		AwsRegion          string
	}
)
