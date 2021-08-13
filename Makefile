VERSION=$(shell bin/glauth64 --version)

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
include pkg/plugins/Makefile

#####################
# High level commands
#####################

# Build and run - used for development
run: setup devrun cleanup

# Run the integration test on linux64 (eventually allow the binary to be set)
test: runtest

# Run build process for all binaries
all: setup binaries verify cleanup

# Run build process for only linux64
fast: setup linux64 verify cleanup

# list of binary formats to build
binaries: linux32 linux64 linuxarm32 linuxarm64 darwin64 win32 win64

# Setup commands to always run
setup: bindata getdeps format

#####################
# Subcommands
#####################

# Run integration test
runtest:
	./scripts/travis/integration-test.sh cleanup

# Get all dependencies
getdeps:
	go get -d ./...

updatetest:
	./scripts/travis/integration-test.sh

bindata:
	go get -u github.com/jteeuwen/go-bindata/... && ${GOPATH}/bin/go-bindata -pkg=assets -o=pkg/assets/bindata.go assets && gofmt -w pkg/assets/bindata.go


cleanup:
	rm pkg/assets/bindata.go

format:
	go fmt

devrun:
	go run ${BUILD_FILES} -c sample-simple.cfg

linux32:
	GOOS=linux GOARCH=386 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth32 ${BUILD_FILES} && cd bin && sha256sum glauth32 > glauth32.sha256

linux64:
	GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth64 ${BUILD_FILES} && cd bin && sha256sum glauth64 > glauth64.sha256

linuxarm32:
	GOOS=linux GOARCH=arm go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth-arm32 ${BUILD_FILES} && cd bin && sha256sum glauth-arm32 > glauth-arm32.sha256

linuxarm64:
	GOOS=linux GOARCH=arm64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth-arm64 ${BUILD_FILES} && cd bin && sha256sum glauth-arm64 > glauth-arm64.sha256

darwin64:
	GOOS=darwin GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauthOSX ${BUILD_FILES} && cd bin && sha256sum glauthOSX > glauthOSX.sha256

darwinarm64:
	GOOS=darwin GOARCH=arm64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauthOSX-arm64 ${BUILD_FILES} && cd bin && sha256sum glauthOSX-arm64 > glauthOSX-arm64.sha256

win32:
	GOOS=windows GOARCH=386 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth-win32 ${BUILD_FILES} && cd bin && sha256sum glauth-win32 > glauth-win32.sha256

win64:
	GOOS=windows GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/glauth-win64 ${BUILD_FILES} && cd bin && sha256sum glauth-win64 > glauth-win64.sha256


verify:
	cd bin && sha256sum *.sha256 -c && cd ../;
