VERSION=$(shell bin/linuxamd64/glauth --version)

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
BUILD_VARS=-s -w -X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}
BUILD_FILES=glauth.go
TRIM_FLAGS=-gcflags "all=-trimpath=${PWD}" -asmflags "all=-trimpath=${PWD}"

# Plugins
include pkg/plugins/*/Makefile

#####################
# High level commands
#####################

# Build and run - used for development
run: setup devrun

# Run the integration test on linuxamd64 (eventually allow the binary to be set)
test: runtest

# Run build process for all binaries
all: setup binaries verify

# Run build process for only linuxamd64
fast: setup linuxamd64

# list of binary formats to build
binaries: linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64

# Setup commands to always run
setup: getdeps format

#####################
# Subcommands
#####################

# Run integration test
runtest:
	./scripts/ci/integration-test.sh cleanup

# Get all dependencies
getdeps:
	go get -d ./...

updatetest:
	./scripts/ci/integration-test.sh

format:
	go fmt

devrun:
	go run ${BUILD_FILES} -c sample-simple.cfg

linux386:
	mkdir -p bin/$@ && GOOS=linux GOARCH=386 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

linuxamd64:
	mkdir -p bin/$@ && GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

linuxarm:
	mkdir -p bin/$@ && GOOS=linux GOARCH=arm go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

linuxarm64:
	mkdir -p bin/$@ && GOOS=linux GOARCH=arm64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

darwinamd64:
	mkdir -p bin/$@ && GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

darwinarm64:
	mkdir -p bin/$@ && GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

win386:
	mkdir -p bin/$@ && GOOS=windows GOARCH=386 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

winamd64:
	mkdir -p bin/$@ && GOOS=windows GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/$@/glauth ${BUILD_FILES} && cd bin/$@ && sha256sum glauth > glauth.sha256

verify:
	@for binary in linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64; do cd bin/$$binary && sha256sum glauth.sha256 -c && cd ../..; done

release: linux386 linuxamd64 linuxarm linuxarm64 win386 winamd64

release_darwin: darwinamd64 darwinarm64

pull-plugin:
	@git submodule add $U $M && \
	(for pkg in $$(cat $$M/go.mod | awk '/^require [a-z]/{print $$2} /^\)/{rblock=0} rblock{if($$4!="indirect" && $$1!~"glauth"){print $$1}} /^require \(/{rblock=1}'); do if [ "$$(grep $$pkg go.mod &>/dev/null)" = "" ]; then go get $$pkg; fi; done)

pull-plugins:
	@U=https://github.com/glauth/glauth-sqlite M=pkg/plugins/glauth-sqlite make pull-plugin && \
	U=https://github.com/glauth/glauth-mysql M=pkg/plugins/glauth-mysql make pull-plugin && \
	U=https://github.com/glauth/glauth-postgres M=pkg/plugins/glauth-postgres make pull-plugin && \
	U=https://github.com/glauth/glauth-pam M=pkg/plugins/glauth-pam make pull-plugin

forget-plugin:
	rm -rf $M ../.git/modules/v2/$M && \
	git config --remove-section submodule.v2/$M && \
	git rm --cache $M && \
	go mod tidy

forget-plugins:
	@M=pkg/plugins/glauth-sqlite make forget-plugin && \
	M=pkg/plugins/glauth-mysql make forget-plugin && \
	M=pkg/plugins/glauth-postgres make forget-plugin && \
	M=pkg/plugins/glauth-pam make forget-plugin

testxgo:
	xgo -v -ldflags="${BUILD_VARS}" -go 1.18.1 -out glauth -buildvcs=false --targets=linux/amd64 .

testxgo3:
	xgo -v -ldflags="${BUILD_VARS}" -go 1.18.1 -out glauth-plugin -buildvcs=false -buildmode=plugin --targets=linux/amd64 --pkg pkg/plugins/glauth-sqlite/sqlite.go .

testxgo4:
	xgo -v -ldflags="${BUILD_VARS}" -go 1.18.1 -out glauth-plugin -buildvcs=false -buildmode=plugin --targets=linux/amd64 --pkg pkg/plugins/glauth-mysql/mysql.go .
