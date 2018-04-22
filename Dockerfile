#################
# Build Step
#################

FROM golang:latest as build
MAINTAINER Ben Yanke <ben@benyanke.com>

# Setup work env
RUN mkdir /app /tmp/gocode
ADD . /app/
WORKDIR /app

# Required envs for GO
ENV GOPATH=/tmp/gocode
ENV GOOS=linux
ENV GOARCH=amd64

# Install deps
RUN go get -d ./...

# Build
RUN go build -o /app/glauth glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

#################
# Run Step
#################

FROM golang:latest as run
MAINTAINER Ben Yanke <ben@benyanke.com>

# Copies a sample config to be used if a volume isn't mounted with user's config
ADD sample-simple.cfg /app/config/config.cfg

# Copy binary from build container
COPY --from=build /app/glauth /app/glauth

# Copy docker specific scripts from build container
COPY --from=build /app/docker/start.sh /app/docker/
COPY --from=build /app/docker/default-config.cfg /app/docker/

# Expose web and LDAP ports
EXPOSE 389 5555

# To use your own config, mount /app/config, and place config.cfg in mounted volume
# CMD ["/app/glauth", "-c", "/app/config/config.cfg"]
CMD ["/bin/bash", "/app/docker/start.sh"]
