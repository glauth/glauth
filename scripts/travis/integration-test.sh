#!/bin/bash


# Ensure ldap utils are installed (for example - when running this outside of travis)
if [[ `which ldapsearch` ]]; then
	echo "ldap-utils installed - continuing";
else
	sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils || exit 1;
fi

# Start in background, capture PID
$TRAVIS_BUILD_DIR/bin/glauth64 -c "$TRAVIS_BUILD_DIR/$1" &
glauthPid="$!"

echo "Running at $glauthPid"


# Run tests here
sleep 2;

# Kill saved PID when done
kill $glauthPid;
echo "done."
