
# GLAuth: LDAP authentication server for developers
Go-lang LDAP Authentication (GLAuth) is a secure, easy-to-use, LDAP server w/ configurable backends.

[![Travis Build - Master](https://img.shields.io/travis/glauth/glauth.svg)](https://travis-ci.org/glauth/glauth)
[![Last Commit](https://img.shields.io/github/last-commit/glauth/glauth.svg)](https://github.com/glauth/glauth/graphs/commit-activity)

[![](https://img.shields.io/docker/build/glauth/glauth.svg)](https://hub.docker.com/r/glauth/glauth/)
[![DockerHub Image Size](https://img.shields.io/imagelayers/image-size/glauth/glauth/latest.svg)](https://hub.docker.com/r/glauth/glauth/)

[![Maintainability](https://img.shields.io/codeclimate/maintainability/glauth/glauth.svg)](https://codeclimate.com/github/glauth/glauth/maintainability)
[![Test Coverage](https://img.shields.io/codeclimate/coverage/glauth/glauth.svg)](https://codeclimate.com/github/glauth/glauth/test_coverage)

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


### OpenSSH keys:
GLAuth can store a user's SSH authorized keys.  Add one or more keys per user as shown above, then setup the goklp helper: https://github.com/appliedtrust/goklp

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
