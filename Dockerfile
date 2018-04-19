FROM golang:latest 

MAINTAINER Ben Yanke <ben@benyanke.com>

RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN go build -o main . 
CMD ["/app/main"]
