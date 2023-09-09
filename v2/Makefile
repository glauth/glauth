.DEFAULT_GOAL := help

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
TRIM_FLAGS=-trimpath

# Targets
MAIN_TARGETS=linux/amd64,linux/386,linux/arm64,linux/arm-7,darwin/amd64,darwin/arm64,windows/amd64,windows/386
PLUGIN_TARGETS=linux/amd64,linux/386,linux/arm64,linux/arm-7,darwin/amd64,darwin/arm64

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

#test: @ runs the integration test on linuxamd64 (eventually allow the binary to be set)
test: runtest

#all: @ run build process for all binaries
all: setup binaries verify

#fast: @ run build process for only linuxamd64
fast: setup linuxamd64

#binaries: @ list of binary formats to build
binaries: linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64

#setup: @ setup commands to always run
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

pull-plugin:
	@git submodule add $U $M && \
	(for pkg in $$(cat $$M/go.mod | awk '/^require [a-z]/{print $$2} /^\)/{rblock=0} rblock{if($$4!="indirect" && $$1!~"glauth"){print $$1}} /^require \(/{rblock=1}'); do if [ "$$(grep $$pkg go.mod &>/dev/null)" = "" ]; then go get $$pkg; fi; done)

pull-base-plugins:
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
	for pkg in pkg/plugins/*/go.mod; do\
		P=$$(echo $$pkg | cut -d'/' -f 3) M=$$(dirname $$pkg) make forget-plugin;\
	done

releasemain:
	@xgo -v -ldflags="${BUILD_VARS}" -trimpath -go 1.18.1 -out glauth -dest bin -buildvcs=false --targets="${MAIN_TARGETS}" .

releaseplugin:
	@xgo -v -ldflags="${BUILD_VARS}" -trimpath -go 1.18.1 -out $P -dest bin -buildvcs=false -buildmode=plugin --targets="${PLUGIN_TARGETS}" --pkg $M/$P.go . && \
	(cd bin && for lib in $$(ls $$P-*); do sudo mv $$lib $$lib.so; done)

releaseplugins:
	@for pkg in pkg/plugins/*/go.mod; do\
		P=$$(echo $$pkg | cut -d'/' -f 3) && make release-$$P;\
	done

releasedockermain:
	$(if $(TAG),,$(error Must set TAG))
	$(if $(REPO),,$(error Must set REPO - glauth or other))
	@mkdir -p docker/assets/linux/amd64 docker/assets/linux/arm64 docker/assets/linux/arm/v7 && \
	cp -f bin/glauth-linux-amd64 docker/assets/linux/amd64/glauth && \
	cp -f bin/glauth-linux-arm64 docker/assets/linux/arm64/glauth && \
	cp -f bin/glauth-linux-arm-7 docker/assets/linux/arm/v7/glauth && \
	docker buildx build --tag $$REPO/glauth:$$TAG -t $$REPO/glauth:latest -f docker/Dockerfile-standalone --platform linux/amd64,linux/arm64,linux/arm/v7 --push docker

releasedockerplugins:
	$(if $(TAG),,$(error Must set TAG))
	$(if $(REPO),,$(error Must set REPO - glauth or other))
	@mkdir -p docker/assets/linux/amd64 docker/assets/linux/arm64 docker/assets/linux/arm/v7 && \
	cp -f bin/sqlite-linux-amd64.so docker/assets/linux/amd64/sqlite.so && \
	cp -f bin/sqlite-linux-arm64.so docker/assets/linux/arm64/sqlite.so && \
	cp -f bin/sqlite-linux-arm-7.so docker/assets/linux/arm/v7/sqlite.so && \
	cp -f bin/mysql-linux-amd64.so docker/assets/linux/amd64/mysql.so && \
	cp -f bin/mysql-linux-arm64.so docker/assets/linux/arm64/mysql.so && \
	cp -f bin/mysql-linux-arm-7.so docker/assets/linux/arm/v7/mysql.so && \
	cp -f bin/postgres-linux-amd64.so docker/assets/linux/amd64/postgres.so && \
	cp -f bin/postgres-linux-arm64.so docker/assets/linux/arm64/postgres.so && \
	cp -f bin/postgres-linux-arm-7.so docker/assets/linux/arm/v7/postgres.so && \
	docker buildx build --tag $$REPO/glauth-plugins:$$TAG -t $$REPO/glauth-plugins:latest -f docker/Dockerfile-plugins --platform linux/amd64,linux/arm64,linux/arm/v7 --push docker

releasedocker: releasedockermain releasedockerplugins

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

.PHONY: all run test fast binaries setup getdeps runtest updatetest format devrun linux386 linuxamd64 linuxarm linuxarm64 darwinamd64 darwinarm64 win386 winamd64 verify pull-plugin pull-base-plugins forget-plugin forget-plugins releasemain releaseplugin release releaseplugins releasedockermain releaserdockerplugins releasedocker testdocker
