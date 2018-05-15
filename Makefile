VERSION=$(shell bin/glauth64 --version)

# GIT_COMMIT=$(shell git rev-list -1 HEAD)

# Returns the commit hash if the git staging directory is clean - in other words, if the commit hash accurately reflects the code being built
# Otherwise, return empty
# GIT_COMMIT = $(shell if [[ $(git status | grep -E "working (tree|directory) clean" | wc -l) -eq "0" ]] ; then echo "hi"; git rev-list -1 HEAD ; fi)
GIT_COMMIT=$(shell git rev-list -1 HEAD )
BUILD_TIME=$(shell date --utc +%Y%m%d_%H%M%SZ)
GIT_CLEAN=$(shell git status | grep -E "working (tree|directory) clean" | wc -l)

run:
	go run glauth.go bindata.go ldapbackend.go webapi.go configbackend.go -c glauth.cfg

all: bindata binaries verify

binaries: bindata linux32 linux64 linuxarm32 linuxarm64 darwin64 win32 win64

bindata:
	go-bindata -pkg=main assets && gofmt -w .


linux32: bindata
	GOOS=linux GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth32 > glauth32.sha256

linux64: bindata
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth64 > glauth64.sha256

linuxarm32: bindata
	GOOS=linux GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth-arm32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-arm32 > glauth-arm32.sha256

linuxarm64: bindata
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth-arm64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-arm64 > glauth-arm64.sha256

darwin64: bindata
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauthOSX glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauthOSX > glauthOSX.sha256

win32: bindata
	GOOS=windows GOARCH=386 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth-win32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-win32 > glauth-win32.sha256

win64: bindata
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME} -X main.GitClean=${GIT_CLEAN}" -o bin/glauth-win64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-win64 > glauth-win64.sha256


verify:
	cd bin && sha256sum *.sha256 -c && cd ../;
