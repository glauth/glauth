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
RUN apk add --no-cache git bzr

# Install deps
RUN go get -d -v ./...

# Build
RUN go build -o /app/glauth glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

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
COPY --from=build /app/docker/start.sh /app/docker/
COPY --from=build /app/docker/default-config.cfg /app/docker/

# Install init
RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64
RUN chmod +x /usr/local/bin/dumb-init

# Expose web and LDAP ports
EXPOSE 389 5555

# To use your own config, mount /app/config, and place config.cfg in mounted volume
ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]

# CMD ["/app/glauth", "-c", "/app/config/config.cfg"]
CMD ["/bin/sh", "/app/docker/start.sh"]
