#####################
# Plugins Targets
#####################

# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugins: plugin_mysql plugin_postgres plugin_sqlite

plugin_mysql: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/mysql.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/mysql.so: pkg/plugins/mysql.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_postgres: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/postgres.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/postgres.so: pkg/plugins/postgres.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_sqlite: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/sqlite.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/sqlite.so: pkg/plugins/sqlite.go pkg/plugins/basesqlhandler.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugins_darwin: plugins_darwin_amd64 plugins_darwin_arm64

plugins_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugins

plugins_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugins

plugins_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugins

plugins_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugins
