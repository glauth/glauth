#!/bin/bash


# Ensure ldap utils are installed (for example - when running this outside of travis)
if [[ ! `which ldapsearch` ]]; then
	sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils || exit 1;
fi

# Start in background, capture PID
$TRAVIS_BUILD_DIR/bin/glauth64 -c "$TRAVIS_BUILD_DIR/scripts/travis/test-config.cfg" &> /dev/null &
# $TRAVIS_BUILD_DIR/bin/glauth64 -c "$TRAVIS_BUILD_DIR/scripts/travis/test-config.cfg" &
glauthPid="$!"

echo "Running glauth at PID=$glauthPid"

# Sleep a second, to ensure it comes online successfully
sleep 1;


FAIL="0"

# Arguments:
#    $1 - query
#    $2 - name of snapshot
function snapshotTest() {

  goodResults="$TRAVIS_BUILD_DIR/scripts/travis/good-results"
  testResults="$TRAVIS_BUILD_DIR/scripts/travis/test-results"

  mkdir "$testResults" &> /dev/null

  # Run tests here
  ldapsearch -LLL \
    -H ldap://localhost:3893 \
    -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com \
    -w mysecret \
    -x -bdc=glauth,dc=com \
    "$1" > "$testResults/$2"

    THISFAIL="0"
    diff -u "$goodResults/$2" "$testResults/$2" || THISFAIL="1"

  if [[ "$THISFAIL" = "0" ]] ; then
    echo "  - PASS : '$2'";
  else
    echo "  - FAIL : '$2'";
    FAIL="1"
    exit 255;
  fi

}


echo "";
echo "";
echo "RUNNING TESTS:"
echo "";

# Regular single-user fetches
snapshotTest "cn=hackers" userFetchTest0
snapshotTest "cn=johndoe" userFetchTest1
snapshotTest "cn=serviceuser" userFetchTest2

# Test result of fetching nonexistent users
snapshotTest "cn=fakeuser" userFetchNonexistentUser0
snapshotTest "cn=janedoe" userFetchNonexistentUser1

echo "";
echo "";

# Kill saved PID when done
# However - throw the fail flag if the process isn't there (ie, exited prematurely)
echo "Killing glauth"
kill "$glauthPid" || FAIL="1"

if [[ "$FAIL" = "0" ]] ; then
  echo "Integration test success"
  exit 0;
else
  echo "Integration test FAILED"
  exit 255;
fi
