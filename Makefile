VERSION=$(shell bin/glauth64 --version)


run:
	go run glauth.go bindata.go ldapbackend.go webapi.go configbackend.go -c glauth.cfg

all: bindata binaries verify

binaries: bindata linux32 linux64 linuxarm64 darwin64

bindata:
	go-bindata -pkg=main assets && gofmt -w .

linux32: bindata
	echo "Building Linux32 binary" && GOOS=linux GOARCH=386 go build -o bin/glauth32 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth32 > glauth32.sha256

linux64: bindata
	echo "Building Linux64 binary" && GOOS=linux GOARCH=amd64 go build -o bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth64 > glauth64.sha256

linuxarm64: bindata
	echo "Building Linux-Arm64 binary" && GOOS=linux GOARCH=arm64 go build -o bin/glauth-arm64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauth-arm64 > glauth-arm64.sha256

darwin64: bindata
	echo "Building MacOS binary" && GOOS=darwin GOARCH=amd64 go build -o bin/glauthOSX glauth.go bindata.go ldapbackend.go webapi.go configbackend.go && cd bin && sha256sum glauthOSX > glauthOSX.sha256


verify:
	cd bin && sha256sum *.sha256 -c && cd ../;
