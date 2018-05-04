# GLAuth: LDAP authentication server for developers
Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory.
* Store your user directory in S3 or MySQL, or proxy to existing LDAP servers.

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Install GLAuth on a test server
  1. Clone the repo: `git clone https://github.com/nmcclain/glauth`
  2. Start the GLAuth server: `cd glauth; sudo bin/glauth32 -c sample-simple.cfg`
2. Test with traditional LDAP tools
  1. `ldapsearch -LLL -H ldap://localhost:389 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`

### Usage:
```
glauth: securely expose your LDAP for external auth

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
```

### Configuration:
GLAuth can be deployed as a single server using only a local configuration file.  This is great for testing, or for production if you use a tool like Puppet/Chef/Ansible:
```unix
glauth -c glauth.cfg
```
Here's a sample config wth hardcoded users and groups:
```toml
[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
[[users]]
  name = "hackers"
  unixid = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a"   # dogood
  sshkeys = [ "ssh-dss AAAAB3..." ]
[[groups]]
  name = "superheros"
  unixid = 5501
```
To create the password SHA hash, use this command: `echo -n "mysecret" | openssl dgst -sha256`
Instead of a local configuration file, GLAuth can fetch its configuration from S3.  This is an easy way to ensure redundant GLAuth servers are always in-sync.
```unix
glauth -c s3://bucketname/glauth.cfg
```
In order to use S3, you must set your AWS credentials.  Either:

1. set the -K and -S command-line flags  **OR**
2. set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.

More configuration options are documented here: https://github.com/nmcclain/glauth/blob/master/sample-simple.cfg

### Required Fields
 * Name
   * The user's username
 * ou
   * ID of the user's primary group
 * uidbumber
   * The user's unix user id
 * sshPublicKey
   * Specify an array of public keys

### Optional Fields
 * givenname
   * First name
   * Example: John
   * default = blank
 * sn
   * Last name
   * Example: Doe
   * default = blank
 * disabled
   * Specify if account is active.
   * Set to 'true' (without quotes) to make the LDAP entry add 'AccountStatus = inactive'
   * default = false (active)
 * mail
   * Specify an email
   * example: jdoe@example.com
   * default = blank
 * loginshell
   * Specify a different login shell for the user
   * Example: /bin/sh, or /sbin/nologin
   * default = /bin/bash
 * homedirectory
   * Specify an overridden home directory for the user
   * Example: /home/itadmin
   * default = /home/[username]
 * otpsecret
   * Specify OTP secret used to validate OTP passcode
   * Example: 4W6YXGBIJASNVDY1
   * default = blank
 * yubikey
   * Specify Yubikey ID for maching Yubikey OTP against the user
   * Example: cccjgjgkhcbb
   * default = blank


### OpenSSH keys:
GLAuth can store a user's SSH authorized keys.  Add one or more keys per user as shown above, then setup the goklp helper: https://github.com/appliedtrust/goklp

### OTP Tokens
GLAuth can be configured to accept OTP tokens as appended to a users password. Support is added for both TOTP tokens and Yubikey OTP tokens.

#### TOTP configuration
To enable TOTP authentication on a user, you can use a tool [like this](https://freeotp.github.io/qrcode.html) to generate a QR code (pick 'Timeout' and optionally let it generate a random secret for you), which can be scanned and used with the [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en) app. To enable TOTP authentication, configure the `otpsecret` for the user with the TOTP secret.

#### Yubikey configuration
For Yubikey OTP token authentication, first [configure your Yubikey](https://www.yubico.com/products/services-software/personalization-tools/yubikey-otp/). After this, make sure to [request a `Client ID` and `Secret key` pair](https://upgrade.yubico.com/getapikey/). 

Now configure the the `yubikeyclientid` and `yubikeysecret` fields in the general section in the configuration file.

To enable Yubikey OTP authentication for a user, you must specify their Yubikey ID on the users `yubikey` field. The Yubikey ID is the first 12 characters of the Yubikey OTP, as explained in the below chart.

![Yubikey OTP](https://developers.yubico.com/OTP/otp_details.png)

When a user has been configured with either one of the OTP options, the OTP authentication is required for the user. If both are configured, either one will work.

### Backends:
For advanced users, GLAuth supports pluggable backends.  Currently, it can use a local file, S3 or an existing LDAP infrastructure.  In the future, we hope to have backends that support Mongo, SQL, and other datastores.
```toml
[backend]
  datastore = "ldap"
  servers = [ "ldaps://server1:636", "ldaps://server2:636" ]
```

### Production:
Any of the architectures above will work for production.  Just remember:

 * Always use legit SSL certs for production!
 
### Building:
You'll need go-bindata to build GLAuth: 
```unix
go get github.com/jteeuwen/go-bindata/...
```
