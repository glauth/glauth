#####################
# Plugins Targets
#####################

# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugins: plugin_mysql plugin_postgres plugin_sqlite

plugin_mysql: bin/mysql.so

bin/mysql.so: pkg/plugins/mysql.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_postgres: bin/postgres.so

bin/postgres.so: pkg/plugins/postgres.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_sqlite: bin/sqlite.so

bin/sqlite.so: pkg/plugins/sqlite.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^
