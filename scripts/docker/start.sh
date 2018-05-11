#!/bin/sh

# Copy config file if it doesn't exist so that the app can start
if [ ! -f /app/config/config.cfg ] ; then
  cp /app/docker/default-config.cfg /app/config/config.cfg;
 fi

# Run app
/app/glauth -c /app/config/config.cfg
