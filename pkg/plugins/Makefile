#####################
# Plugins Targets
#####################

plugin_mysql: bin/mysql.so

bin/mysql.so: pkg/plugins/mysql.go pkg/plugins/basesqlhandler.go
	GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_postgres: bin/postgres.so

bin/postgres.so: pkg/plugins/postgres.go pkg/plugins/basesqlhandler.go
	GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_sqlite: bin/sqlite.so

bin/sqlite.so: pkg/plugins/sqlite.go pkg/plugins/basesqlhandler.go
	GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^