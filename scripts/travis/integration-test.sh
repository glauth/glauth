#!/bin/bash

sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils &&

"$1" -c "$2" &
glauthPid="$!"

echo "Running at $glauthPid"
sleep 2;
kill $glauthPid;
echo "done."
