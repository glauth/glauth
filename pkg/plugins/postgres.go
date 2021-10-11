package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/glauth/glauth/pkg/handler"
)

type PostgresBackend struct {
}

func NewPostgresHandler(opts ...handler.Option) handler.Handler {
	backend := PostgresBackend{}
	return NewDatabaseHandler(backend, opts...)
}

func (b PostgresBackend) GetDriverName() string {
	return "postgres"
}

func (b PostgresBackend) FindUserQuery(criterion string) string {
	return fmt.Sprintf("SELECT uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey FROM users WHERE %s=$1", criterion)
}

func (b PostgresBackend) FindGroupQuery() string {
	return "SELECT gidnumber FROM groups WHERE lower(name)=$1"
}

func (b PostgresBackend) FindPosixAccountsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups,givenname,sn,mail,loginshell,homedirectory,disabled FROM users"
}

func (b PostgresBackend) MemoizeGroupsQuery() string {
	return `
		SELECT g1.name,g1.gidnumber,ig.includegroupid
		FROM groups g1
		LEFT JOIN includegroups ig ON g1.gidnumber=ig.parentgroupid
		LEFT JOIN groups g2 ON ig.includegroupid=g2.gidnumber`
}

func (b PostgresBackend) GetGroupMembersQuery() string {
	return "SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups FROM users u WHERE lower(u.name)=$1"
}

func (b PostgresBackend) GetGroupMemberIDsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups FROM users"
}

func (b PostgresBackend) GetUserCapabilitiesQuery() string {
	return "SELECT action,object FROM capabilities WHERE userid=$1"
}

// Create db/schema if necessary
func (b PostgresBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups TEXT DEFAULT '',
	givenname TEXT DEFAULT '',
	sn TEXT DEFAULT '',
	mail TEXT DEFAULT '',
	loginshell TEXT DEFAULT '',
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
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id SERIAL PRIMARY KEY, name TEXT NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id SERIAL PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id SERIAL PRIMARY KEY, userid INTEGER NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL)")
	statement.Exec()
}
