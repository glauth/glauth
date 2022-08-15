package config

import "time"

// config file
type Backend struct {
	BaseDN                    string
	Datastore                 string
	Insecure                  bool     // For LDAP and owncloud backend only
	Servers                   []string // For LDAP and owncloud backend only
	NameFormat                string
	GroupFormat               string
	SSHKeyAttr                string
	UseGraphAPI               bool   // For ownCloud backend only
	Plugin                    string // Path to plugin library, for plugin backend only
	PluginHandler             string // Name of plugin's main handler function
	Database                  string // For Database backends only
	GroupWithSearchCapability string // For PamLinux backend only
	AnonymousDSE              bool   // For Config and Database backends only
}
type Helper struct {
	Enabled       bool
	BaseDN        string
	Datastore     string
	Plugin        string // Path to plugin library, for plugin backend only
	PluginHandler string // Name of plugin's main handler function
	Database      string // For MySQL backend only TODO REname to match plugin
}
type Frontend struct {
	AllowedBaseDNs []string // For LDAP backend only
	Listen         string
	Cert           string
	Key            string
	TLS            bool
}
type LDAP struct {
	Enabled bool
	Listen  string
}
type LDAPS struct {
	Enabled bool
	Listen  string
	Cert    string
	Key     string
}
type API struct {
	Cert        string
	Enabled     bool
	Internals   bool
	Key         string
	Listen      string
	SecretToken string
	TLS         bool
}
type Behaviors struct {
	IgnoreCapabilities    bool
	LimitFailedBinds      bool
	NumberOfFailedBinds   int
	PeriodOfFailedBinds   time.Duration
	BlockFailedBindsFor   time.Duration
	PruneSourceTableEvery time.Duration
	PruneSourcesOlderThan time.Duration
}
type Capability struct {
	Action string
	Object string
}

// UserAuthenticator authenticates a user via custom auth from a backend
type UserAuthenticator func(user *User, pw string) error
type User struct {
	Name          string
	OtherGroups   []int
	PassSHA256    string
	PassBcrypt    string
	PassAppSHA256 []string
	PassAppBcrypt []string
	PassAppCustom UserAuthenticator
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
type Group struct {
	Name          string
	UnixID        int // TODO: remove after deprecating UnixID on User and Group
	GIDNumber     int
	IncludeGroups []int
}
type Config struct {
	API                API
	Backend            Backend // Deprecated
	Backends           []Backend
	Helper             Helper
	Behaviors          Behaviors
	Debug              bool
	WatchConfig        bool
	YubikeyClientID    string
	YubikeySecret      string
	Frontend           Frontend
	LDAP               LDAP
	LDAPS              LDAPS
	Groups             []Group
	Syslog             bool
	Users              []User
	ConfigFile         string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	AwsRegion          string
}
