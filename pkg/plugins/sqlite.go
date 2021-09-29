package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/glauth/glauth/pkg/handler"
)

type SqliteBackend struct {
}

func NewSQLiteHandler(opts ...handler.Option) handler.Handler {
	backend := SqliteBackend{}
	return NewDatabaseHandler(backend, opts...)
}

func (b SqliteBackend) GetDriverName() string {
	return "sqlite3"
}

func (b SqliteBackend) FindUserQuery(criterion string) string {
	return fmt.Sprintf("SELECT uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey FROM users WHERE %s=?", criterion)
}

func (b SqliteBackend) FindGroupQuery() string {
	return "SELECT gidnumber FROM groups WHERE lower(name)=?"
}

func (b SqliteBackend) FindPosixAccountsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups,givenname,sn,mail,loginshell,homedirectory,disabled FROM users"
}

func (b SqliteBackend) MemoizeGroupsQuery() string {
	return `
		SELECT g1.name,g1.gidnumber,ig.includegroupid
		FROM groups g1
		LEFT JOIN includegroups ig ON g1.gidnumber=ig.parentgroupid
		LEFT JOIN groups g2 ON ig.includegroupid=g2.gidnumber`
}

func (b SqliteBackend) GetGroupMembersQuery() string {
	return "SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups FROM users u WHERE lower(u.name)=?"
}

func (b SqliteBackend) GetGroupMemberIDsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups FROM users"
}

// Create db/schema if necessary
func (b SqliteBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups TEXT DEFAULT '',
	givenname TEXT DEFAULT '',
	sn TEXT DEFAULT '',
	mail TEXT DEFAULT '',
	loginshell TYEXT DEFAULT '',
	homedirectory TEXT DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 TEXT DEFAULT '',
	passbcrypt TEXT DEFAULT '',
	otpsecret TEXT DEFAULT '',
	yubikey TEXT DEFAULT '')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id INTEGER PRIMARY KEY, userid INTEGER NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL)")
	statement.Exec()
}
