#!/bin/bash

img="localhost/glauth-dev"

sudo docker rmi -f "$img"

sudo docker build -f Dockerfile -t "$img" .

sudo docker run -P "$img"
