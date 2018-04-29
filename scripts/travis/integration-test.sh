#!/bin/bash

sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils &&

$TRAVIS_BUILD_DIR/glauth -c "$TRAVIS_BUILD_DIR/$1" &
glauthPid="$!"

echo "Running at $glauthPid"
sleep 2;
kill $glauthPid;
echo "done."
