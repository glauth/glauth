package config

// config file
type Backend struct {
	BaseDN      string
	Datastore   string
	Insecure    bool     // For LDAP backend only
	Servers     []string // For LDAP backend only
	NameFormat  string
	GroupFormat string
	SSHKeyAttr  string
	UseGraphAPI bool // For ownCloud backend only
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
	Key         string
	Listen      string
	SecretToken string
	TLS         bool
}
type User struct {
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
type Group struct {
	Name          string
	UnixID        int
	IncludeGroups []int
}
type Config struct {
	API                API
	Backend            Backend
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
