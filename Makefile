VERSION=$(shell bin/glauth64 --version)


GIT_COMMIT=$(shell git rev-list -1 HEAD )
BUILD_TIME=$(shell date --utc +%Y%m%d_%H%M%SZ)
GIT_CLEAN=$(shell git status | grep -E "working (tree|directory) clean" | wc -l)

# Last git tag
LAST_GIT_TAG=$(shell git describe --abbrev=0 --tags 2> /dev/null)

# this=1 if the current commit is the tagged commit (ie, if this is a release build)
GIT_IS_TAG_COMMIT=$(shell git describe --abbrev=0 --tags > /dev/null 2> /dev/null && echo "1" || echo "0")

# Used when a tag isn't available
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

# Build variables
BUILD_VARS=-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}
BUILD_FILES=glauth.go bindata.go ldapbackend.go webapi.go configbackend.go sqlitebackend.go localtoolbox.go

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
setup: getdeps bindata format

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
	go get -u github.com/jteeuwen/go-bindata/... && ${GOPATH}/bin/go-bindata -pkg=main assets && gofmt -w bindata.go


cleanup:
	rm bindata.go

format:
	go fmt

devrun:
	go run ${BUILD_FILES} -c glauth.cfg


# Here is the first hint that cross-compilers are a package management headache for the Ubuntu maintainers.
# When gcc-multilib is kicked out by its frennemy gcc-multilib-arm, it's really a dance of symlinks
# so this the only dependency we can rely on for now:
/usr/share/doc/gcc-multilib:
	sudo apt-get install gcc-multilib

linux32: /usr/share/doc/gcc-multilib
	GOOS=linux CGO_ENABLED=1 GOARCH=386 go build -ldflags "${BUILD_VARS}" -o bin/glauth32 ${BUILD_FILES} && cd bin && sha256sum glauth32 > glauth32.sha256

linux64:
	GOOS=linux GOARCH=amd64 go build -ldflags "${BUILD_VARS}" -o bin/glauth64 ${BUILD_FILES} && cd bin && sha256sum glauth64 > glauth64.sha256

# Note that gcc-multilib and gcc-multilib-arm cannot coexist. Worse, when one is removed, the other will not create the necessary
# links to the asm directory, out of fear of creating a circular dependency.
/usr/bin/arm-linux-gnueabihf-gcc:
	sudo apt-get install gcc-multilib-arm-linux-gnueabihf && sudo ln -sfn /usr/include/asm-generic /usr/include/asm

linuxarm32: /usr/bin/arm-linux-gnueabihf-gcc
	GOOS=linux CGO_ENABLED=1 CC=arm-linux-gnueabihf-gcc GOARCH=arm go build -ldflags "${BUILD_VARS}" -o bin/glauth-arm32 ${BUILD_FILES} && cd bin && sha256sum glauth-arm32 > glauth-arm32.sha256

linuxarm64:
	GGOOS=linux CGO_ENABLED=1 CC_FOR_TARGET=arm-linux-gnueabihf-gcc GGOARCH=arm64 go build -ldflags "${BUILD_VARS}" -o bin/glauth-arm64 ${BUILD_FILES} && cd bin && sha256sum glauth-arm64 > glauth-arm64.sha256

# Darwin cross-compiler
osxcross:
	git clone https://github.com/tpoechtrager/osxcross && \
	cd osxcross && \
	wget -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz && \
	mv MacOSX10.10.sdk.tar.xz tarballs/ && \
	UNATTENDED=yes OSX_VERSION_MIN=10.10 ./build.sh

darwin64: osxcross
	PATH=$$PWD/osxcross/target/bin:$$PATH GOOS=darwin CGO_ENABLED=1 CC=o64-clang GOARCH=amd64 go build -ldflags "${BUILD_VARS}" -o bin/glauthOSX ${BUILD_FILES} && cd bin && sha256sum glauthOSX > glauthOSX.sha256

# Windows cross-compiler
/usr/bin/x86_64-w64-mingw32-gcc:
	sudo apt-get install gcc-mingw-w64

win32: /usr/bin/x86_64-w64-mingw32-gcc
	GOOS=windows CGO_ENABLED=1 CC=i686-w64-mingw32-gcc GOARCH=386 go build -ldflags "${BUILD_VARS}" -o bin/glauth-win32 ${BUILD_FILES} && cd bin && sha256sum glauth-win32 > glauth-win32.sha256

win64: /usr/bin/x86_64-w64-mingw32-gcc
	GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOARCH=amd64 go build -ldflags "${BUILD_VARS}" -o bin/glauth-win64 ${BUILD_FILES} && cd bin && sha256sum glauth-win64 > glauth-win64.sha256


verify:
	cd bin && sha256sum *.sha256 -c && cd ../;

.PHONY: linux32 linux64 linuxarm32 linuxarm64 darwin64 win32 win64 verify
