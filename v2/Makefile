.DEFAULT_GOAL := help

MAKEFLAGS += --no-print-directory

VERSION=$(shell if [ -x bin/linuxamd64/glauth ]; then bin/linuxamd64/glauth --version; else bin/glauth-linux-amd64 --version; fi)

GIT_COMMIT=$(shell git rev-list -1 HEAD )
BUILD_TIME=$(shell date -u +%Y%m%d_%H%M%SZ)
GIT_CLEAN=$(shell git status | grep -E "working (tree|directory) clean" | wc -l | sed 's/^[ ]*//')

# Last git tag
LAST_GIT_TAG=$(shell git describe --abbrev=0 --tags 2> /dev/null)

# this=1 if the current commit is the tagged commit (ie, if this is a release build)
GIT_IS_TAG_COMMIT=$(shell git describe --abbrev=0 --tags > /dev/null 2> /dev/null && echo "1" || echo "0")

# Used when a tag isn't available
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

# Build variables
BUILD_VARS?=-s -w
BUILD_FILES=.
TRIM_FLAGS>?=-trimpath
BUILD_TAGS?=noembed

# Targets
MAIN_TARGETS?=linux/amd64,linux/386,linux/arm64,linux/arm-7,linux/riscv64,darwin/amd64,darwin/arm64,windows/amd64,windows/386
PLUGIN_TARGETS?=linux/amd64,linux/386,linux/arm64,linux/arm-7,linux/riscv64,darwin/amd64,darwin/arm64
EMBED_TARGETS?=windows/amd64

# For release process
GO_RELEASE_V=$(shell go version | { read _ _ v _; echo $${v#go}; })

# Build
GOOS?=linux
GOARCH?=amd64

# Plugins
-include pkg/plugins/*/Makefile

#####################
# High level commands
#####################

#help: @ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#' | sed -E 's/Makefile.//' | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#run: @ build and run - used for development
run: setup devrun

mocks:
	go install go.uber.org/mock/mockgen@v0.3.0
	# generate gomocks
	go generate ./...
.PHONY: mocks

vet:
	-go vet ./...
.PHONY: vet
#test: @ runs package, root integration, and shell integration tests
test: mocks vet
	go test -v -cover -coverprofile coverage.out ./pkg/... ./internal/... .
	$(MAKE) runtest
#all: @ run build process for all binaries
all: setup binaries verify

#fast: @ run build process for only linuxamd64
fast: setup linuxamd64

#fastdebug: @ run build process for only linuxamd64 in debug mode
fastdebug: setup linuxamd64debug

#binaries: @ list of binary formats to build
binaries: linux386 linuxamd64 linuxarm linuxarm64 linuxriscv64 darwinamd64 darwinarm64 win386 winamd64

#setup: @ setup commands to always run
setup: getdeps format

#####################
# Subcommands
#####################
#	@echo \- removing any changes and pulling latest master && \
#	git reset --hard HEAD >/dev/null 2>&1 && \
#	git checkout master >/dev/null 2>&1 && \
#	git pull >/dev/null 2>&1 && \

prepbuild:
	echo \- taking care of ignore files && \
	sudo rm -rf bin/* >/dev/null && \
	echo \- cleaning up plugins remnants && \
	make forget-plugins && \
	make remember-plugins

forget-embed:
	@if [ -f pkg/server/embed_sqlite.go ]; then \
		mv pkg/server/embed_sqlite.go /tmp/; \
	fi

remember-embed:
	@if [ ! -f pkg/server/embed_sqlite.go ]; then \
		mv /tmp/embed_sqlite.go pkg/server/; \
	fi

# Run integration test
runtest:
	./scripts/ci/integration-test.sh cleanup

# Get all dependencies
getdeps:
	go get -d ./...

updatetest:
	./scripts/ci/integration-test.sh

format:
	go fmt ./...

devrun:
	go run ${BUILD_FILES} -c sample-simple.cfg

#testplugin: @ start GLAuth with a dynamically loaded plugin and stop it cleanly
GLAUTH_BIN?=bin/glauth-linux-amd64
PLUGIN_BIN?=bin/sqlite-linux-amd64.so
PLUGIN_CONFIG?=pkg/plugins/glauth-sqlite/sample-database.cfg
PLUGIN_LDAP_PORT?=13893
PLUGIN_API_PORT?=15555

testplugin:
	@set -e; \
	test -x "$(GLAUTH_BIN)"; \
	test -r "$(PLUGIN_BIN)"; \
	test -f "$(PLUGIN_CONFIG)"; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	sed \
		-e 's#^[[:space:]]*plugin = .*#  plugin = "$(abspath $(PLUGIN_BIN))"#' \
		-e "s#^[[:space:]]*database = .*#  database = \"$$tmpdir/gl.db\"#" \
		-e 's#listen = "0.0.0.0:3893"#listen = "127.0.0.1:$(PLUGIN_LDAP_PORT)"#' \
		-e 's#listen = "0.0.0.0:5555"#listen = "127.0.0.1:$(PLUGIN_API_PORT)"#' \
		"$(PLUGIN_CONFIG)" > "$$tmpdir/config.cfg"; \
	"$(GLAUTH_BIN)" -c "$$tmpdir/config.cfg" > "$$tmpdir/glauth.log" 2>&1 & \
	pid=$$!; \
	sleep 2; \
	if ! kill -0 "$$pid" 2>/dev/null; then \
		set +e; wait "$$pid"; status=$$?; set -e; \
		cat "$$tmpdir/glauth.log"; \
		exit $$status; \
	fi; \
	kill -TERM "$$pid"; \
	set +e; wait "$$pid"; status=$$?; set -e; \
	cat "$$tmpdir/glauth.log"; \
	exit $$status

mkbindir:
	@echo "create directory bin/$(GOOS)$(GOARCH)"
	@mkdir -p bin/$(GOOS)$(GOARCH)
.PHONY: mkbindir

build: mkbindir
	@go build ${TRIM_FLAGS} -tags ${BUILD_TAGS} -ldflags "${BUILD_VARS}" -o bin/$(GOOS)$(GOARCH)/glauth -buildvcs .
	$(MAKE) sha256
.PHONY: build

builddebug: mkbindir
	@go build ${TRIM_FLAGS} -tags ${BUILD_TAGS} -gcflags="all=-N -l" -o bin/$(GOOS)$(GOARCH)/glauth -buildvcs .
	$(MAKE) sha256
.PHONY: builddebug

sha256:
	@sha256sum bin/$(GOOS)$(GOARCH)/glauth > bin/$(GOOS)$(GOARCH)/glauth.sha256
.PHONY: sha256

linuxamd64debug:
	GOOS=linux GOARCH=amd64 $(MAKE) builddebug

linux386:
	GOOS=linux GOARCH=386 $(MAKE) build

linuxamd64:
	GOOS=linux GOARCH=amd64 $(MAKE) build

linuxarm:
	GOOS=linux GOARCH=arm $(MAKE) build

linuxarm64:
	GOOS=linux GOARCH=arm64 $(MAKE) build

linuxriscv64:
	GOOS=linux GOARCH=riscv64 $(MAKE) build

testing:
	mkdir -p pkg/embed && \
	cat pkg/plugins/glauth-sqlite/sqlite.go | sed -e 's/func main() {}//' -e 's/^package main/package embed/' > pkg/embed/sqlite.go  && \
	go mod tidy && \
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 BUILD_TAGS=embedsqlite $(MAKE) build && \
	rm -rf pkg/embed

darwinamd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(MAKE) build

darwinarm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(MAKE) build

win386:
	GOOS=windows GOARCH=386 $(MAKE) build

winamd64:
	GOOS=windows GOARCH=amd64 $(MAKE) build

verify:
	@for binary in linux386 linuxamd64 linuxarm linuxarm64 linuxriscv64 darwinamd64 darwinarm64 win386 winamd64; do cd bin/$$binary && sha256sum glauth.sha256 -c && cd ../..; done

pull-plugin-dependencies:
	@echo Pulling dependencies for $$M
	# the go.work screws up interacting with a submodule
	# We query the plugin for all of it's direct dependencies not the Main module and not Indirect
	# Then we use `go list -m` to check to see if the dependency is already used in the main glauth project
	# if it is we ignore it because we don't know what differences it may have
	# if it isn't we use `go get` to add the plugins dependency to the glauth go.mod file
	@for pkg in $$(cd "$$M"; GOWORK='off' go list -m -f "{{if and (not .Main) (ne .Indirect true)}}{{.Path}}{{if .Version}}@{{.Version}}{{end}}{{end}}" all | grep -v github.com/glauth/glauth/v2); do \
			if ! go list -m "$${pkg%@*}" >/dev/null 2>&1; then \
				echo getting $$pkg; \
				go get "$$pkg"; \
			fi; \
	done;


#prepare-plugins-buid: @ pull plugins dependencies for local building
prepare-plugins-build:
	@M=pkg/plugins/glauth-sqlite make pull-plugin-dependencies && \
	M=pkg/plugins/glauth-mysql make pull-plugin-dependencies && \
	M=pkg/plugins/glauth-postgres make pull-plugin-dependencies && \
	M=pkg/plugins/glauth-pam make pull-plugin-dependencies

forget-plugin:
	rm -rf $M ../.git/modules/v2/$M; \
	git config --remove-section submodule.v2/$M; \
	git rm --cache $M; \
	go mod tidy; \
	true

#forget-plugin: @ remove plugins, restoring original file structure
forget-plugins:
	for pkg in pkg/plugins/*; do \
		if [ -d "$$pkg" ]; then \
			P=$$(echo $$pkg | cut -d'/' -f 3) M=$$pkg make forget-plugin >/dev/null 2>&1;\
		fi; \
	done; \
	rm -rf buildlogs

remember-plugins:
	cd ../ && \
	for module in $$(cat .gitmodules | awk '/path =/{P=$$3} /url =/{print $$3 "," P}'); do \
		git submodule add $${module%%,*} $${module#*,}; \
	done; \
	git submodule update --init --recursive

_buildmain:
	@xgo -v -ldflags="${BUILD_VARS}" -trimpath -go ${GO_RELEASE_V} -out glauth -dest bin -buildvcs=false --targets="${MAIN_TARGETS}" .

#buildmain: @ build main binaries for distribution
buildmain: prepbuild _buildmain

buildsingleembed:
	# Remove embed folder. The only thing in it should be main.go with `package embed`
	rm -rf ./pkg/embed
	# Ensure embed folder exists
	mkdir -p pkg/embed
	# Copy in plugin
	cp -r "$M"/* pkg/embed
	# Delete any go modules. `make pull-plugin-dependencies` should be ran separately before this
	rm -f pkg/embed/go.mod pkg/embed/go.sum
	# Do a naive package name replacement
	find pkg/embed -name '*.go' -exec sed -E -i -e 's/func main\(\)\s*\{\s*\}\s*//' -e 's/func New\w+Handler\(opts \.\.\.handler\.Option\) handler\.Handler \{/func NewHandler(opts ...handler.Option) handler.Handler {/g' -e 's/^package main/package embed/' '{}' '+'
	# Tidy because go sucks
	go mod tidy
	# Actually build the thing
	go build -ldflags="${BUILD_VARS}" --tags=$T -trimpath -o bin/glauth -buildvcs=false .
	# Remove all traces of the package
	rm -rf pkg/embed
	mkdir -p pkg/embed
	# Put the default go file back
	echo 'package embed' >pkg/embed/main.go
	# Tidy because go sucks
	go mod tidy

_buildmainembeds:
	M=pkg/plugins/glauth-sqlite T=embed make pull-plugin-dependencies buildsingleembed

#buildmainembeds: @ build main binaries for distribution, including embedded plugins
buildmainembeds: prepbuild _buildmainembeds

buildplugin:
ifeq ($P,pam)
	xgo -v -ldflags="${BUILD_VARS}" -trimpath -go ${GO_RELEASE_V} -out $P -dest bin -buildvcs=false -buildmode=plugin --targets="${PLUGIN_TARGETS}" --pkg $M/$P.go --bringupcmd 'apt update && apt install -y libpam0g-dev' .
else
	xgo -v -ldflags="${BUILD_VARS}" -trimpath -go ${GO_RELEASE_V} -out $P -dest bin -buildvcs=false -buildmode=plugin --targets="${PLUGIN_TARGETS}" --pkg $M/$P.go .
endif
	(cd bin && for lib in $$(ls $$P-* | grep -v \.so$$); do sudo mv $$lib $$lib.so; done);

_buildplugins: prepare-plugins-build
	for pkg in pkg/plugins/*; do \
		if [ -d "$$pkg" ]; then \
			M=pkg/plugins/$$(echo $$pkg | cut -d'/' -f 3) && P=$$(echo $$M | grep -oP 'glauth-\K\w+') && M=$$M P=$$P make buildplugin;\
		fi; \
	done; \

#buildplugins: @ build base plugins for distribution
buildplugins: forget-embed _buildplugins remember-embed

_checkdockerauth:
	@if ! grep -q "index.docker.io" $(HOME)/.docker/config.json; then \
		echo "❌ Not logged in to Docker Hub (index.docker.io not found in config)."; \
		exit 1; \
	fi; \
	if ! grep -q "ghcr.io" $(HOME)/.docker/config.json; then \
		echo "❌ Not logged in to GitHub Hub (ghcr.io not found in config)."; \
		exit 1; \
	fi

builddockermain:
	$(if $(TAG),,$(error ❌ Must set TAG))
	$(if $(REPO),,$(error ❌ Must set REPO - glauth or other))
	@mkdir -p docker/assets/linux/amd64 docker/assets/linux/arm64 docker/assets/linux/arm/v7 docker/assets/linux/riscv64 && \
	cp -f bin/glauth-linux-amd64 docker/assets/linux/amd64/glauth && \
	cp -f bin/glauth-linux-arm64 docker/assets/linux/arm64/glauth && \
	cp -f bin/glauth-linux-arm-7 docker/assets/linux/arm/v7/glauth && \
    cp -f bin/glauth-linux-riscv64 docker/assets/linux/riscv64/glauth && \
	docker buildx build --tag ghcr.io/$$REPO/glauth:$$TAG -t ghcr.io/$$REPO/glauth:latest -f docker/Dockerfile-standalone --platform linux/amd64,linux/arm64,linux/arm/v7,linux/riscv64 --push docker && \
	docker buildx build --tag $$REPO/glauth:$$TAG -t $$REPO/glauth:latest -f docker/Dockerfile-standalone --platform linux/amd64,linux/arm64,linux/arm/v7,linux/riscv64 --push docker

builddockerplugins:
	$(if $(TAG),,$(error ❌ Must set TAG))
	$(if $(REPO),,$(error ❌ Must set REPO - glauth or other))
	@mkdir -p docker/assets/linux/amd64 docker/assets/linux/arm64 docker/assets/linux/arm/v7 docker/assets/linux/riscv64 && \
	cp -f bin/sqlite-linux-amd64.so docker/assets/linux/amd64/sqlite.so && \
	cp -f bin/sqlite-linux-arm64.so docker/assets/linux/arm64/sqlite.so && \
	cp -f bin/sqlite-linux-arm-7.so docker/assets/linux/arm/v7/sqlite.so && \
	cp -f bin/sqlite-linux-riscv64.so docker/assets/linux/riscv64/sqlite.so && \
	cp -f bin/mysql-linux-amd64.so docker/assets/linux/amd64/mysql.so && \
	cp -f bin/mysql-linux-arm64.so docker/assets/linux/arm64/mysql.so && \
	cp -f bin/mysql-linux-arm-7.so docker/assets/linux/arm/v7/mysql.so && \
	cp -f bin/mysql-linux-riscv64.so docker/assets/linux/riscv64/mysql.so && \
	cp -f bin/postgres-linux-amd64.so docker/assets/linux/amd64/postgres.so && \
	cp -f bin/postgres-linux-arm64.so docker/assets/linux/arm64/postgres.so && \
	cp -f bin/postgres-linux-arm-7.so docker/assets/linux/arm/v7/postgres.so && \
	cp -f bin/postgres-linux-riscv64.so docker/assets/linux/riscv64/postgres.so && \
	docker buildx build --tag ghcr.io/$$REPO/glauth-plugins:$$TAG -t ghcr.io/$$REPO/glauth-plugins:latest -f docker/Dockerfile-plugins --platform linux/amd64,linux/arm64,linux/arm/v7,linux/riscv64 --push docker && \
	docker buildx build --tag $$REPO/glauth-plugins:$$TAG -t $$REPO/glauth-plugins:latest -f docker/Dockerfile-plugins --platform linux/amd64,linux/arm64,linux/arm/v7,linux/riscv64 --push docker

builddocker: _checkdockerauth builddockermain builddockerplugins

buildeverything: prepbuild forget-embed _buildplugins _buildmain testplugin remember-embed _buildmainembeds builddocker

#testdocker: @ run integration test using docker
testdocker:
	$(if $(REPO),,$(error Must set REPO - glauth or other))
	@echo "==> Cleaning up any existing image to be on the safe side..." && \
	(for image in $$(docker image ls -q "$$REPO/glauth*"); do \
		for container in $$(docker container ls -a -q -f ancestor=$$image); do \
			docker stop $$container; \
			while [ "$$(docker container ls -q -f ancestor=$$image)" != "" ]; do sleep 1; done; \
			docker rm $$container; \
		done; \
		docker rmi $$image; \
	done) && \
	echo "==> Running glauth main container..." && \
	docker run -d --name glauth-test -p 3893:3893 $$REPO/glauth:latest && \
	sleep 5 && \
	if [ "$$(ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers | grep posixAccount)" != "" ]; then \
		echo "Checked: Glauth is responding properly to ldapsearch query."; \
	else \
		echo "glauth check did not pass. Aborting."; \
		exit 1; \
	fi && \
	echo "==> Stopping glauth main container..." && \
	docker stop glauth-test && \
	while [ "$$(docker ps -q -f name=glauth-test)" != "" ]; do sleep 1; done; \
	docker rm glauth-test && \
	echo "==> Running glauth plugins container..." && \
	docker run -d --name glauth-test -p 3893:3893 $$REPO/glauth-plugins:latest && \
	sleep 5 && \
	if [ "$$(ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers | grep posixAccount)" != "" ]; then \
		echo "Checked: Glauth is responding properly to ldapsearch query."; \
	else \
		echo "glauth check did not pass. Aborting."; \
		exit 1; \
	fi && \
	echo "==> Stopping glauth plugins container..." && \
	docker stop glauth-test  && \
	while [ "$$(docker ps -q -f name=glauth-test)" != "" ]; do sleep 1; done; \
	docker rm glauth-test && \
	echo "==> Testing complete."

.PHONY: all \
	prepbuild run test fast binaries setup getdeps runtest updatetest format devrun \
	linux386 linuxamd64 linuxarm linuxarm64 linuxriscv64 darwinamd64 darwinarm64 win386 winamd64 verify \
	pull-plugin pull-base-plugins forget-plugin forget-plugins buildmain buildplugin build \
	buildplugins builddockermain builddockerplugins builddocker testdocker testplugin buildeverything
