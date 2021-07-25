# GLAuth Plugins

This folder contains plugins; that is, backends that are not compiled in GLAuth by default.

To quote 'Butonic' (Jörn Friedrich Dreyer):

> Just keep the 'lightweight' in mind.

To build either back-end, type
```
make plugin_name
```
where 'name' is the plugin's name; so, for instance: `make plugin_sqlite`

To build back-ends for specific architectures, specify `PLUGIN_OS` and `PLUGIN_ARCH` --
 For instance, to build the sqlite plugin for the new Mac M1s:
 ```
make plugin_sqlite PLUGIN_OS=darwin PLUGIN_ARCH=arm64
 ```

## Database Plugins

To use a database plugin, edit the configuration file (see pkg/plugins/sample-database.cfg) so that:

```
...
[backend]
  datastore = "plugin"
  plugin = "dynamic library you created using the previous 'make' command"
  database = "database connection string"
...
```
so, let's say you built the 'sqlite' plugin, you would now specify its library: `database = sqlite.so`

### SQLite, MySQL, Postgres

Tables:
- users, groups are self-explanatory
- includegroups store the 'includegroups' relationships
- othergroups, on the other hand, are a comma-separated list found in the users table (performance)

Here is how to insert example data using your database's REPL (more detailed information can be found in pkg/plugins/sample-database.cfg)

```sql
INSERT INTO users(name, unixid, primarygroup, passsha256) VALUES('hackers', 5001, 5501, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO groups(name, unixid) VALUES('superheros', 5501);
INSERT INTO groups(name, unixid) VALUES('crusaders', 5502);
INSERT INTO groups(name, unixid) VALUES('civilians', 5503);
INSERT INTO groups(name, unixid) VALUES('caped', 5504);
INSERT INTO groups(name, unixid) VALUES('lovesailing', 5505);
INSERT INTO groups(name, unixid) VALUES('smoker', 5506);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5503, 5501);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5504, 5502);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5504, 5501);
INSERT INTO users(name, unixid, primarygroup, passsha256) VALUES('user1', 5001, 5501, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, unixid, primarygroup, passsha256) VALUES('user2', 5002, 5502, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, unixid, primarygroup, passsha256) VALUES('user3', 5003, 5504, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, unixid, primarygroup, passsha256, othergroups) VALUES('user4', 5004, 5504, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a', '5505,5506');
```
This should be equivalent to this configuration:
```text
[[users]]
  name = "hackers"
  unixid = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[users]]
  name = "user1"
  unixid = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[users]]
  name = "user2"
  unixid = 5002
  primarygroup = 5502
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[users]]
  name = "user3"
  unixid = 5003
  primarygroup = 5504
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[users]]
  name = "user4"
  unixid = 5003
  primarygroup = 5504
  othergroups = [5505, 5506]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[groups]]
  name = "superheros"
  unixid = 5501

[[groups]]
  name = "crusaders"
  unixid = 5502

[[groups]]
  name = "civilians"
  unixid = 5503
  includegroups = [ 5501 ]

[[groups]]
  name = "caped"
  unixid = 5504
  includegroups = [ 5502, 5501 ]
```
and LDAP should return these `memberOf` values:
```text
uid: user1
ou: superheros
memberOf: cn=caped,ou=groups,dc=militate,dc=com
memberOf: cn=civilians,ou=groups,dc=militate,dc=com
memberOf: cn=superheros,ou=groups,dc=militate,dc=com

uid: user2
ou: crusaders
memberOf: cn=caped,ou=groups,dc=militate,dc=com
memberOf: cn=crusaders,ou=groups,dc=militate,dc=com

uid: user3
ou: caped
memberOf: cn=caped,ou=groups,dc=militate,dc=com

uid: user4
ou: caped
memberOf: cn=caped,ou=groups,dc=militate,dc=com
memberOf: cn=lovesailing,ou=groups,dc=militate,dc=com
memberOf: cn=smoker,ou=groups,dc=militate,dc=com
```
If you have the ldap client package installed, this can be easily confirmed by running
```
ldapsearch  -H ldap://localhost:3893 -D cn=hackers,ou=superheros,dc=glauth,dc=com -w dogood -x -bdc=glauth,dc=com cn=user1
```
and so on.
