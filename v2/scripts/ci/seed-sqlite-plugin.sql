-- Seed data for TestSQLitePlugin. The schema itself is created by the plugin's
-- CreateSchema() on first start, so this file only inserts rows.

INSERT INTO ldapgroups(name, gidnumber)
  VALUES('superheros', 5501);
INSERT INTO ldapgroups(name, gidnumber)
  VALUES('svcaccts', 5502);
INSERT INTO ldapgroups(name, gidnumber)
  VALUES('civilians', 5503);
INSERT INTO ldapgroups(name, gidnumber)
  VALUES('caped', 5504);
INSERT INTO ldapgroups(name, gidnumber)
  VALUES('lovesailing', 5505);
INSERT INTO ldapgroups(name, gidnumber)
  VALUES('smoker', 5506);
INSERT INTO includegroups(parentgroupid, includegroupid)
  VALUES(5503, 5501);
INSERT INTO includegroups(parentgroupid, includegroupid)
  VALUES(5504, 5502);
INSERT INTO includegroups(parentgroupid, includegroupid)
  VALUES(5504, 5501);
INSERT INTO users(name, uidnumber, primarygroup, passsha256)
  VALUES('hackers', 5001, 5501,
    '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, uidnumber, primarygroup, passsha256)
  VALUES('johndoe', 5002, 5502,
    '6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a');
INSERT INTO users(name, mail, uidnumber, primarygroup, passsha256)
  VALUES('serviceuser', 'serviceuser@example.com', 5003, 5502,
    '652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0');
INSERT INTO users(name, uidnumber, primarygroup, passsha256, othergroups)
  VALUES('user4', 5004, 5504,
    '652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0',
    '5505,5506');
INSERT INTO capabilities(userid, action, object)
  VALUES(5001, 'search', 'ou=superheros,dc=glauth,dc=com');
INSERT INTO capabilities(userid, action, object)
  VALUES(5003, 'search', '*');
