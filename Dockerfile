#################
# Build Step
#################

FROM golang:latest as build

MAINTAINER Ben Yanke <ben@benyanke.com>

RUN mkdir /app /tmp/gocode
ADD . /app/
WORKDIR /app

# Required Envs for GO
ENV GOPATH=/tmp/gocode

# Install deps
RUN go get -d ./...

# Build
# RUN rm -f /app/bin/glauth64 && GOOS=linux GOARCH=amd64 go build -o /app/bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go
RUN GOOS=linux GOARCH=amd64 go build -o /app/bin/glauth64 glauth.go bindata.go ldapbackend.go webapi.go configbackend.go

# RUN for GOOS in darwin linux; do
#   for GOARCH in 386 amd64; do
#     go build -v -o /app/bin/glauth-$GOOS-$GOARCH
#   done
# done



#################
# Test Step
#################

FROM golang:alpine as run

MAINTAINER Ben Yanke <ben@benyanke.com>

RUN apk --no-cache add ca-certificates

ADD sample-simple.cfg /app/sample-simple.cfg
WORKDIR /app

COPY --from=build /app/bin/glauth64 /app/glauth64

# CMD /app/glauth64 -c /app/sample-simple.cfg
CMD ["/app/glauth64", "-c", "/app/sample-simple.cfg"]
