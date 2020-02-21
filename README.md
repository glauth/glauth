# GLAuth: LDAP authentication server for developers
Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

[![Travis Build - Master](https://img.shields.io/travis/glauth/glauth.svg)](https://travis-ci.org/glauth/glauth)
[![Last Commit](https://img.shields.io/github/last-commit/glauth/glauth.svg)](https://github.com/glauth/glauth/graphs/commit-activity)

[![](https://img.shields.io/docker/build/glauth/glauth.svg)](https://hub.docker.com/r/glauth/glauth/)
[![DockerHub Image Size](https://img.shields.io/microbadger/image-size/glauth/glauth.svg)](https://hub.docker.com/r/glauth/glauth/)

[![Maintainability](https://img.shields.io/codeclimate/maintainability/glauth/glauth.svg)](https://codeclimate.com/github/glauth/glauth/maintainability)
[![Test Coverage](https://img.shields.io/codeclimate/coverage/glauth/glauth.svg)](https://codeclimate.com/github/glauth/glauth/test_coverage)

[![Donate via Paypal](https://img.shields.io/badge/Donate-PayPal-green.svg)](http://paypal.me/benyanke)

* Centrally manage accounts across your infrastructure
* Centrally manage SSH keys, Linux accounts, and passwords for cloud servers.
* Lightweight alternative to OpenLDAP and Active Directory for development, or a homelab.
* Store your user directory in a local file, S3 or proxy to existing LDAP servers.

Use it to centralize account management across your Linux servers, your OSX machines, and your support applications (Jenkins, Apache/Nginx, Graylog2, and many more!).

### Contributing
Please base all PRs on [dev](https://github.com/nmcclain/glauth/tree/dev), not master.

### Quickstart
This quickstart is a great way to try out GLAuth in a non-production environment.  *Be warned that you should take the extra steps to setup SSL (TLS) for production use!*

1. Download a precompiled binary from the [releases](https://github.com/glauth/glauth/releases) page.
2. Download the [example config file](https://github.com/glauth/glauth/blob/master/sample-simple.cfg).
3. Start the GLAuth server, referencing the path to the desired config file with `-c`.
   - `sudo ./glauth64 -c sample-simple.cfg`
4. Test with traditional LDAP tools
   - For example: `ldapsearch -LLL -H ldap://localhost:389 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers`



### Make Commands

Note - makefile uses git data to inject build-time variables. For best results, run in the context of the git repo.

*make all* - run build binaries for platforms

*make fast* - run build for only linux 64 bit

*make run* - wrapper for the 'go run' command, setting up the needed tooling

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

More configuration options are documented here: https://github.com/glauth/glauth/blob/master/sample-simple.cfg

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

# Other Architectures
A small note about other architectures: while I expect the code is, for the most part, system-independent, there is not a good (and free) CI system which can be easily used to continuously test releases on ARM, BSD, Linux-32bit, and Windows. As such, all of the non-linux-64bit packages are provided as is. The extent of testing on these packages consists solely of cross-compiling for these architectures from a linux 64 bit system.

We will accept PRs which fix bugs on these platforms, but be aware these binaries will not be tested regularly, and instead are provided for the convenience of those who feel comfortable with this.
 
### Building:
You'll need go-bindata to build GLAuth. Then use the Makefile.
```unix
go get github.com/jteeuwen/go-bindata/...
make all
```

## Stargazers over time

[![Stargazers over time](https://starcharts.herokuapp.com/glauth/glauth.svg)](https://starcharts.herokuapp.com/glauth/glauth)

### Support

Support the ongoing development of GLAuth!

**Paypal**

[![Donate via Paypal](https://img.shields.io/badge/Donate-PayPal-green.svg)](http://paypal.me/benyanke)


**Bitcoin Address**

39z2Zkoc24LsuiqCQNFe7QrX4da3mzbGjK
