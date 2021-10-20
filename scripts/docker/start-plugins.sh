#!/bin/sh

# Copy config file if it doesn't exist so that the app can start
if [ ! -f /app/config/config.cfg ] ; then
  echo "Config file not found at /app/config/config.cfg"
  echo "Copying example configuration file to run."
  mkdir -p /app/config
  cp /app/docker/default-config-plugins.cfg /app/config/config.cfg || exit 1
  # This file will be ignored when switching away from the default (sqlite)
  cp /app/docker/gl.db /app/config/gl.db || exit 1
 fi


echo "";
echo "Version and build information:";
echo "";

# Output version string to logs
/app/glauth --version


echo "";
echo "Starting GLauth now.";
echo "";

# Run app
cd /app
/app/glauth -c /app/config/config.cfg

echo ""
echo "GLauth has exited."
echo "Exiting."
