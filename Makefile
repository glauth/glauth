VERSION=$(shell bin/glauth64 --version)


run:
	go run glauth.go bindata.go ldapbackend.go webapi.go configbackend.go -c glauth.cfg

all: bindata binaries 

binaries: bindata linux32 linux64 darwin64

bindata:
	go-bindata -pkg=main assets

linux32: bindata
	GOOS=linux GOARCH=386 go build -o bin/glauth32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

linux64: bindata
	GOOS=linux GOARCH=amd64 go build -o bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

darwin64: bindata
	GOOS=darwin GOARCH=amd64 go build -o bin/glauthOSX glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

