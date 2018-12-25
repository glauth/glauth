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

# Only needed for alpine builds
RUN apk add --no-cache git bzr make

# Install deps
RUN go get -d -v ./...

# Run go-bindata to embed data for API
RUN go get -u github.com/jteeuwen/go-bindata/... && $GOPATH/bin/go-bindata -pkg=main assets && gofmt -w bindata.go

# Build and copy final result
RUN make linux64 && cp ./bin/glauth64 /app/glauth

#################
# Run Step
#################

FROM golang:alpine as run
MAINTAINER Ben Yanke <ben@benyanke.com>

# Copies a sample config to be used if a volume isn't mounted with user's config
ADD sample-simple.cfg /app/config/config.cfg

# Copy binary from build container
COPY --from=build /app/glauth /app/glauth

# Copy docker specific scripts from build container
COPY --from=build /app/scripts/docker/start.sh /app/docker/
COPY --from=build /app/scripts/docker/default-config.cfg /app/docker/

# Install ldapsearch for container health checks, then ensure ldapsearch is installed
RUN apk update && apk add --no-cache openldap-clients && which ldapsearch && rm -rf /var/cache/apk/*

# Install init
RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64 && chmod +x /usr/local/bin/dumb-init

# Expose web and LDAP ports
EXPOSE 389 636 5555

ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["/bin/sh", "/app/docker/start.sh"]

