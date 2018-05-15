VERSION=$(shell bin/glauth64 --version)

GIT_COMMIT=$(shell git rev-list -1 HEAD )
BUILD_TIME=$(shell date --utc +%Y%m%d_%H%M%SZ)
GIT_CLEAN=$(shell git status | grep -E "working (tree|directory) clean" | wc -l)

# Last git tag
# LAST_GIT_TAG=$(shell git describe --abbrev=0 --tags 2> /dev/null)
LAST_GIT_TAG=$(shell echo "v1.0.1")

# this=1 if the current commit is the tagged commit (ie, if this is a release build)
GIT_IS_TAG_COMMIT=$(shell echo "0")

# Used when a tag isn't available
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

run:
	go run glauth.go bindata.go ldapbackend.go webapi.go configbackend.go -c glauth.cfg

all: bindata binaries verify

fast: bindata linux64 verify

binaries: bindata linux32 linux64 linuxarm32 linuxarm64 darwin64 win32 win64

bindata:
	go-bindata -pkg=main assets && gofmt -w .


linux32: bindata
	GOOS=linux GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth32 > glauth32.sha256

linux64: bindata
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth64 > glauth64.sha256

linuxarm32: bindata
	GOOS=linux GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth-arm32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-arm32 > glauth-arm32.sha256

linuxarm64: bindata
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth-arm64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-arm64 > glauth-arm64.sha256

darwin64: bindata
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauthOSX glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauthOSX > glauthOSX.sha256

win32: bindata
	GOOS=windows GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth-win32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-win32 > glauth-win32.sha256

win64: bindata
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN} -X main.LastGitTag=${LAST_GIT_TAG} -X main.GitTagIsCommit=${GIT_IS_TAG_COMMIT}" -o bin/glauth-win64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-win64 > glauth-win64.sha256

verify:
	cd bin && sha256sum *.sha256 -c && cd ../;
