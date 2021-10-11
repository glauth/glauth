package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"

	"github.com/glauth/glauth/pkg/handler"
)

type MysqlBackend struct {
}

func NewMySQLHandler(opts ...handler.Option) handler.Handler {
	backend := MysqlBackend{}
	return NewDatabaseHandler(backend, opts...)
}

func (b MysqlBackend) GetDriverName() string {
	return "mysql"
}

func (b MysqlBackend) FindUserQuery(criterion string) string {
	return fmt.Sprintf("SELECT uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey FROM users WHERE %s=?", criterion)
}

func (b MysqlBackend) FindGroupQuery() string {
	return "SELECT gidnumber FROM groups WHERE lower(name)=?"
}

func (b MysqlBackend) FindPosixAccountsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups,givenname,sn,mail,loginshell,homedirectory,disabled FROM users"
}

func (b MysqlBackend) MemoizeGroupsQuery() string {
	return `
		SELECT g1.name,g1.gidnumber,ig.includegroupid
		FROM groups g1
		LEFT JOIN includegroups ig ON g1.gidnumber=ig.parentgroupid
		LEFT JOIN groups g2 ON ig.includegroupid=g2.gidnumber`
}

func (b MysqlBackend) GetGroupMembersQuery() string {
	return "SELECT u.name,u.uidnumber,u.primarygroup,u.passbcrypt,u.passsha256,u.otpsecret,u.yubikey,u.othergroups FROM users u WHERE lower(u.name)=?"
}

func (b MysqlBackend) GetGroupMemberIDsQuery() string {
	return "SELECT name,uidnumber,primarygroup,passbcrypt,passsha256,otpsecret,yubikey,othergroups FROM users"
}

func (b MysqlBackend) GetUserCapabilitiesQuery() string {
	return "SELECT action,object FROM capabilities WHERE userid=?"
}

// Create db/schema if necessary
func (b MysqlBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(64) NOT NULL,
	uidnumber INTEGER NOT NULL,
	primarygroup INTEGER NOT NULL,
	othergroups VARCHAR(1024) DEFAULT '',
	givenname VARCHAR(64) DEFAULT '',
	sn VARCHAR(64) DEFAULT '',
	mail VARCHAR(254) DEFAULT '',
	loginshell VARCHAR(64) DEFAULT '',
	homedirectory VARCHAR(64) DEFAULT '',
	disabled SMALLINT  DEFAULT 0,
	passsha256 VARCHAR(64) DEFAULT '',
	passbcrypt VARCHAR(64) DEFAULT '',
	otpsecret VARCHAR(64) DEFAULT '',
	yubikey VARCHAR(128) DEFAULT '')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id INTEGER AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64) NOT NULL, gidnumber INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER AUTO_INCREMENT PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS capabilities (id INTEGER AUTO_INCREMENT PRIMARY KEY, userid INTEGER NOT NULL, action VARCHAR(128) NOT NULL, object VARCHAR(128) NOT NULL)")
	statement.Exec()
}
