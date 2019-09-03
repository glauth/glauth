package main

import 	"database/sql"

type SqliteBackend struct {
}

func newSqliteBackend() *SqliteBackend {
	backend := SqliteBackend{}
	return &backend
}

func (b SqliteBackend) getDriverName() string {
	return "sqlite3"
}

func (b SqliteBackend) createSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	name VARCHAR(64) NOT NULL,
	unixid INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups VARCHAR(1024) DEFAULT '',
	givenname VARCHAR(64) DEFAULT '',
	sn VARCHAR(64) DEFAULT '',
	mail VARCHAR(254) DEFAULT '',
	loginshell VARCHAR(64) DEFAULT '',
	homedirectory VARCHAR(64) DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 VARCHAR(64) DEFAULT '',
	otpsecret VARCHAR(64) DEFAULT '',
	yubikey VARCHAR(128) DEFAULT '')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name VARCHAR(64) NOT NULL, unixid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
}