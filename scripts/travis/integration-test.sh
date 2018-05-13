#!/bin/bash

if [[ `which ldapsearch` ]]; then
	echo "ldap-utils installed - continuing";
else
	sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils || exit 1;
fi

$TRAVIS_BUILD_DIR/glauth -c "$TRAVIS_BUILD_DIR/$1" &
glauthPid="$!"

echo "Running at $glauthPid"
sleep 2;
kill $glauthPid;
echo "done."
