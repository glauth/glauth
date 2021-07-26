package main

import (
	"database/sql"

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

func (b MysqlBackend) GetPrepareSymbol() string {
	return "?"
}

// Create db/schema if necessary
func (b MysqlBackend) CreateSchema(db *sql.DB) {
	statement, _ := db.Prepare(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER AUTO_INCREMENT PRIMARY KEY,
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
	passbcrypt VARCHAR(64) DEFAULT '',
	otpsecret VARCHAR(64) DEFAULT '',
	yubikey VARCHAR(128) DEFAULT '')
`)
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_user_name on users(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS groups (id INTEGER AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64) NOT NULL, unixid INTEGER NOT NULL)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE UNIQUE INDEX idx_group_name on groups(name)")
	statement.Exec()
	statement, _ = db.Prepare("CREATE TABLE IF NOT EXISTS includegroups (id INTEGER AUTO_INCREMENT PRIMARY KEY, parentgroupid INTEGER NOT NULL, includegroupid INTEGER NOT NULL)")
	statement.Exec()
}
