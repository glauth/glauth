#################
# Build Step
#################

FROM golang:alpine as build
MAINTAINER Ben Yanke <ben@benyanke.com>

# Setup work env
RUN mkdir /app /tmp/gocode
ADD . /app/
WORKDIR /app


# Required envs for GO
ENV GOPATH=/tmp/gocode
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

# Only needed for alpine builds
RUN apk add --no-cache git make go-bindata

# Run go-bindata to embed data for API
RUN go-bindata -pkg=assets -o=pkg/assets/bindata.go assets
RUN gofmt -w pkg/assets/bindata.go

# Install deps
RUN go get -d -v ./...

# Build and copy final result
RUN uname -a
RUN if [ $(uname -m) == x86_64 ]; then make linux64 && cp ./bin/glauth64 /app/glauth; fi
RUN if [ $(uname -m) == aarch64 ]; then make linuxarm64 && cp ./bin/glauth-arm64 /app/glauth; fi
RUN if [ $(uname -m) == armv7l ]; then make linuxarm32 && cp ./bin/glauth-arm32 /app/glauth; fi

# Check glauth works
RUN /app/glauth --version

#################
# Run Step
#################

FROM alpine as run
MAINTAINER Ben Yanke <ben@benyanke.com>

# Copies a sample config to be used if a volume isn't mounted with user's config
ADD sample-simple.cfg /app/config/config.cfg

# Copy binary from build container
COPY --from=build /app/glauth /app/glauth

# Copy docker specific scripts from build container
COPY --from=build /app/scripts/docker/start.sh /app/docker/
COPY --from=build /app/scripts/docker/default-config.cfg /app/docker/

# Install ldapsearch for container health checks, then ensure ldapsearch is installed
RUN apk update && apk add --no-cache dumb-init openldap-clients && which ldapsearch && rm -rf /var/cache/apk/*

# Install init

# Expose web and LDAP ports
EXPOSE 389 636 5555

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/sh", "/app/docker/start.sh"]

