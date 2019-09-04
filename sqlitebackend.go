package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type SqliteBackend struct {
}

func newSqliteBackend() *SqliteBackend {
	backend := SqliteBackend{}
	return &backend
}

func (b SqliteBackend) getDriverName() string {
	return "sqlite3"
}

func (b SqliteBackend) getPrepareSymbol() string {
	return "?"
}

func (b SqliteBackend) createSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	unixid INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups TEXT DEFAULT '',
	givenname TEXT DEFAULT '',
	sn TEXT DEFAULT '',
	mail TEXT DEFAULT '',
	loginshell TYEXT DEFAULT '',
	homedirectory TEXT DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 TEXT DEFAULT '',
	otpsecret TEXT DEFAULT '',
	yubikey TEXT DEFAULT '')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL, unixid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
}
