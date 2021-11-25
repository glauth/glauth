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
INSERT INTO groups(name, gidnumber) VALUES('superheros', 5501);
INSERT INTO groups(name, gidnumber) VALUES('svcaccts', 5502);
INSERT INTO groups(name, gidnumber) VALUES('civilians', 5503);
INSERT INTO groups(name, gidnumber) VALUES('caped', 5504);
INSERT INTO groups(name, gidnumber) VALUES('lovesailing', 5505);
INSERT INTO groups(name, gidnumber) VALUES('smoker', 5506);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5503, 5501);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5504, 5502);
INSERT INTO includegroups(parentgroupid, includegroupid) VALUES(5504, 5501);
INSERT INTO users(name, uidnumber, primarygroup, passsha256) VALUES('hackers', 5001, 5501, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, uidnumber, primarygroup, passsha256) VALUES('johndoe', 5002, 5502, '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, mail, uidnumber, primarygroup, passsha256) VALUES('serviceuser', "serviceuser@example.com", 5003, 5502, '652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0');
INSERT INTO users(name, uidnumber, primarygroup, passsha256, othergroups, custattr) VALUES('user4', 5004, 5504, '652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0', '5505,5506', '{"employeetype":["Intern","Temp"],"employeenumber":[12345,54321]}');
INSERT INTO capabilities(userid, action, object) VALUES(5001, "search", "ou=superheros,dc=glauth,dc=com");
INSERT INTO capabilities(userid, action, object) VALUES(5003, "search", "*");
```
This should be equivalent to this configuration:
```text
[[users]]
  name = "hackers"
  uidnumber = 5001
  primarygroup = 5501
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "ou=superheros,dc=glauth,dc=com"

[[users]]
  name = "johndoe"
  uidnumber = 5002
  primarygroup = 5502
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood

[[users]]
  name = "serviceuser"
  mail = "serviceuser@example.com"
  uidnumber = 5003
  passsha256 = "652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0" # mysecret
  primarygroup = 5502
    [[users.capabilities]]
    action = "search"
    object = "*"

[[users]]
  name = "user4"
  uidnumber = 5003
  primarygroup = 5504
  othergroups = [5505, 5506]
  passsha256 = "652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0" # mysecret
    [[users.customattributes]]
    employeetype = ["Intern", "Temp"]
    employeenumber = [12345, 54321]

[[groups]]
  name = "superheros"
  gidnumber = 5501

[[groups]]
  name = "svcaccts"
  gidnumber = 5502

[[groups]]
  name = "civilians"
  gidnumber = 5503
  includegroups = [ 5501 ]

[[groups]]
  name = "caped"
  gidnumber = 5504
  includegroups = [ 5502, 5501 ]
```
and LDAP should return these `memberOf` values:
```text
uid: hackers
ou: superheros
memberOf: cn=caped,ou=groups,dc=militate,dc=com
memberOf: cn=civilians,ou=groups,dc=militate,dc=com
memberOf: cn=superheros,ou=groups,dc=militate,dc=com

uid: johndoe
ou: svcaccts
memberOf: cn=caped,ou=groups,dc=militate,dc=com
memberOf: cn=svcaccts,ou=groups,dc=militate,dc=com

uid: serviceuser
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
ldapsearch  -H ldap://localhost:3893 -D cn=hackers,ou=superheros,dc=glauth,dc=com -w dogood -x -bdc=glauth,dc=com cn=hackers
```
and so on.


### Discussion: database schema

While GLAuth is not meant to support millions of user accounts, some decent performance is still expected! In fact, when searching through records using a database query, we should see a performance of O(log n) as opposed to, when searching through a flat config, O(n).

While it would be friendlier to offer related attributes in `join`ed tables, we may end up re-creating a "browse" scenario unintentionally.

For instance, when retrieving custom attributes, we could go through an attribute table: `custattr[userid, attribute, value#n]`

However, this means that a `join` statement between the account table and the custom attribute table would yield the cartesian product of each account x attributes; we would need to iterate through the results and collate them.

Alternatively, in Postgres and MySQL, we could rely on the database engine's built-in support for `crosstab` which pivots the second table's results into corresponding columns. This would not be supported in SQLite and would also mean building pretty nasty execution plans.

**So, what's the decision?**

In GLAuth 2.x, when including information that does not benefit from being normalized (e.g. custom attributes) we are following the "nosql" trend (irony!) of storing this data in a JSON structure.
