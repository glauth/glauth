#!/bin/bash

img="glauth-dev"

sudo docker build -f Dockerfile -t $img .

sudo docker run $img
sudo docker rmi -f $img
