# GLAuth: LDAP authentication server for developers
Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

[![Gitter](https://badges.gitter.im/glauth/community.svg)](https://gitter.im/glauth/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Matrix](https://img.shields.io/badge/chat-%2fjoin%20%23glauth_community:gitter.im-green)](hey)

![GitHub all releases](https://img.shields.io/github/downloads/glauth/glauth/total)
![Docker pulls](https://badgen.net/docker/pulls/glauth/glauth)

![Travis (.com) branch](https://img.shields.io/travis/com/glauth/glauth/dev)
![Docker Automated build](https://img.shields.io/docker/automated/glauth/glauth)

![GitHub last commit (branch)](https://img.shields.io/github/last-commit/glauth/glauth/dev)
![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability-percentage/glauth/glauth)

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory for development, or a homelab.
* Store your user directory in a file, local or in S3; SQL database; or proxy to existing LDAP servers.
* Two Factor Authentication (transparent to applications)
* Multiple backends can be chained to inject features

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### Contributing
- Please base all Pull Requests on [dev](https://github.com/glauth/glauth/tree/dev), not master.
- Format your code autonmatically using `gofmt -d ./` before committing

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Download a precompiled binary from the [releases](https://github.com/glauth/glauth/releases) page.
2. Download the [example config file](https://github.com/glauth/glauth/blob/master/sample-simple.cfg).
3. Start the GLAuth server, referencing the path to the desired config file with `-c`.
   - `./glauth64 -c sample-simple.cfg`
4. Test with traditional LDAP tools
   - For example: `ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`

### Make Commands

Note - makefile uses git data to inject build-time variables. For best results, run in the context of the git repo.

*make all* - run build binaries for platforms

*make fast* - run build for only linux 64 bit

*make run* - wrapper for the 'go run' command, setting up the needed tooling

*make plugins* - build additional (SQL) plugin backends

*make test* - run the integration test on linux64 binary

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
  --ldap <address>          Listen address for the LDAP server.
  --ldaps <address>         Listen address for the LDAPS server.
  --ldaps-cert <cert-file>  Path to cert file for the LDAPS server.
  --ldaps-key <key-file>    Path to key file for the LDAPS server.
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
[[users]]
  name = "uberhackers"
  unixid = 5006
  primarygroup = 5501
  passbcrypt = "243261243130244B62463462656F7265504F762E794F324957746D656541326B4B46596275674A79336A476845764B616D65446169784E41384F4432"   # dogood
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

More configuration options are documented here: https://github.com/glauth/glauth/blob/master/sample-simple.cfg

### Chaining backends

This can be used, for instance, to inject support for Two Factor Authentication for backends that do not support the feature natively:

```
[[backends]]
  datastore = "ldap"
  servers = ["ldap:s//localhost:390"]

[[backends]]
  datastore = "config"

...

[[users]]
  name = "hackers"
  otpsecret = "................"
```


### Required Fields
 * Name
   * The user's username
 * ou
   * ID of the user's primary group
 * uidnumber
   * The user's unix user id
 * sshPublicKey
   * Specify an array of public keys

### Optional Fields
 * otherGroups
   * Array of IDs of groups the user is a member of.
   * Example: [5501, 5002]
   * default = blank
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
   * Example: 3hnvnk4ycv44glzigd6s25j4dougs3rk
   * default = blank
 * passappbcrypt
   * Specify an array of app passwords which can also succesfully bind - these bypass the OTP check. Hash the same way as password.
   * Example: ["c32255dbf6fd6b64883ec8801f793bccfa2a860f2b1ae1315cd95cdac1338efa","4939efa7c87095dacb5e7e8b8cfb3a660fa1f5edcc9108f6d7ec20ea4d6b3a88"]
   * default = blank
 * passappsha256
   * Specify an array of app passwords which can also succesfully bind - these bypass the OTP check. Hash the same way as password.
   * Example: ["c32255dbf6fd6b64883ec8801f793bccfa2a860f2b1ae1315cd95cdac1338efa","4939efa7c87095dacb5e7e8b8cfb3a660fa1f5edcc9108f6d7ec20ea4d6b3a88"]
   * default = blank
 * yubikey
   * Specify Yubikey ID for maching Yubikey OTP against the user
   * Example: cccjgjgkhcbb
   * default = blank

### OpenSSH keys:
GLAuth can store a user's SSH authorized keys.  Add one or more keys per user as shown above, then setup the goklp helper: https://github.com/appliedtrust/goklp

### Strong Passwords
If you are currently using sha256 passwords (`passsha256` or `passappsha256`) moving to strong, salted paswords is recommended. Simply switch to `passbcrypt` and/or `passappbcrypt` password types. Currently (2021) 2<sup>12</sup> is a reasonably good value, depending our your server's CPU.

### Two Factor Authentication
GLAuth can be configured to accept OTP tokens as appended to a users password. Support is added for both **TOTP tokens** (often known by it's most prominent implementation, "Google Authenticator") and **Yubikey OTP tokens**.

When using 2FA, append the 2FA code to the end of the password when authenticating. For example, if your password is "monkey" and your otp is "123456", enter "monkey123456" as your password.

#### TOTP Configuration
To enable TOTP authentication on a user, you can use a tool [like this](https://freeotp.github.io/qrcode.html) to generate a QR code (pick 'Timeout' and optionally let it generate a random secret for you), which can be scanned and used with the [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en) app. To enable TOTP authentication, configure the `otpsecret` for the user with the TOTP secret.

#### App Passwords
Additionally, you can specify an array of password hashes using the `passappsha256` for app passwords. These are not OTP validated, and are hashed in the same way as a password. This allows you to generate a long random string to be used in software which requires the ability to authenticate.

However, app passwords can be used without OTP as well.

#### Yubikey Configuration
For Yubikey OTP token authentication, first [configure your Yubikey](https://www.yubico.com/products/services-software/personalization-tools/yubikey-otp/). After this, make sure to [request a `Client ID` and `Secret key` pair](https://upgrade.yubico.com/getapikey/).

Now configure the `yubikeyclientid` and `yubikeysecret` fields in the general section in the configuration file.

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

# Other Architectures
A small note about other architectures: while I expect the code is, for the most part, system-independent, there is not a good (and free) CI system which can be easily used to continuously test releases on ARM, BSD, Linux-32bit, and Windows. As such, all of the non-linux-64bit packages are provided as is. The extent of testing on these packages consists solely of cross-compiling for these architectures from a linux 64 bit system.

We will accept PRs which fix bugs on these platforms, but be aware these binaries will not be tested regularly, and instead are provided for the convenience of those who feel comfortable with this.

### Building:
You'll need go-bindata to build GLAuth. Then use the Makefile.
```unix
go get github.com/jteeuwen/go-bindata/...
make all
```

# Logging
- using logr with increasing verbosity
  - 0 you always want to see this
  - 1 common logging that you might *possibly* want to turn off (error)
  - 2 warn
  - 3 notice
  - 4 info
  - 6 debug
  - 8 trace
  - 10 I would like to performance test your log collection stack
- errors really are errors that cannot be handled or returned
  - returning a proper LDAP error code is handling an error

# Compatiblity

While our stated goal for GLAuth is to provide the simplest possible authentication server, we keep finding an increasing number of client appliances that are asking fairly "existential" questions of the server. We have been working on providing answers these clients will find satisfactory.

### Root DSE

RFC 4512: "An LDAP server SHALL provide information about itself and other information that is specific to each server.  This is represented as a group of attributes located in the root DSE"

Test: `ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -s base "(objectclass=*)"`

### Subschema Discovery

RFC 4512: "To read schema attributes from the subschema (sub)entry, clients MUST issue a Search operation [RFC4511] where baseObject is the DN of the subschema (sub)entry..."

Test: `ldapsearch -LLL -o ldif-wrap=no -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bcn=schema -s base`

By default, this query will return a very minimal schema (~5 objects) -- you can ask GLAuth to return more comprehensive schemas by unpacking, in the `schema/` directory, the OpenLDAP or FreeIPA schema archives found in the `assets/` directory.

### LDAP Backend: "1.1" attribute

RFC 4511: "A list containing only the OID "1.1" indicates that no attributes are to be returned."

## Stargazers over time

[![Stargazers over time](https://starcharts.herokuapp.com/glauth/glauth.svg)](https://starcharts.herokuapp.com/glauth/glauth)

