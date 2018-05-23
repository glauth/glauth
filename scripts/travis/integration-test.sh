#!/bin/bash

export CLEANUP="$1"

# Get the git working directory base if travis build dir isn't set
if [[ "$TRAVIS_BUILD_DIR" == "" ]] ; then
  export TRAVIS_BUILD_DIR="$(git rev-parse --show-toplevel)"
fi

# This script requires that "$TRAVIS_BUILD_DIR" is set to the repo root

# Ensure ldap utils are installed (for example - when running this outside of travis)
if [[ ! `which ldapsearch` ]]; then
	sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils || exit 1;
fi

# Display version string
echo "";
echo ""
echo "Version string of tested binary:"
"$TRAVIS_BUILD_DIR/bin/glauth64" --version
echo ""

# Start in background, capture PID
"$TRAVIS_BUILD_DIR/bin/glauth64" -c "$TRAVIS_BUILD_DIR/scripts/travis/test-config.cfg" &> /dev/null &
glauthPid="$!"

echo "Running glauth at PID=$glauthPid"

# Sleep 2 sec, to ensure it comes online successfully and stays up
sleep 2;

# Check if process is still running before continuing
ps aux | grep -v "grep" | grep "$glauthPid" &> /dev/null || FAIL="1"

if [[ "$FAIL" = "1" ]] ; then
  echo "Integration test FAILED - process did not remain running > 2 sec"
  exit 255;
fi


FAIL="0"

# Arguments:
#    $1 - query
#    $2 - name of snapshot
function snapshotTest() {

  goodResults="$TRAVIS_BUILD_DIR/scripts/travis/good-results"
  testResults="$TRAVIS_BUILD_DIR/scripts/travis/test-results"

  mkdir "$testResults" &> /dev/null

  # Run tests here
  ldapCmd="ldapsearch -LLL \
    -H ldap://localhost:3893 \
    -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com \
    -w mysecret \
    -x -bdc=glauth,dc=com \
    $1";

    # Run the ldap command, pipe to file
    # "$ldapCmd" &> "$testResults/$2"

    # Useful for debugging - output the command run
    # echo "$ldapCmd";

  ldapsearch -LLL \
    -H ldap://localhost:3893 \
    -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com \
    -w mysecret \
    -x -bdc=glauth,dc=com \
    $1 > "$testResults/$2"


    THISFAIL="0"
    diff -u "$goodResults/$2" "$testResults/$2" || THISFAIL="1"


    if [[ "$CLEANUP" = "cleanup" ]] ; then
      rm -rf "$testResults"
    fi

  if [[ "$THISFAIL" = "0" ]] ; then
    echo "  - PASS : '$2'";
  else
    echo "  - FAIL : '$2'";
    FAIL="1"
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

# List all posixgroups
snapshotTest "\(objectClass=posixgroup\)" posixGroupList0
snapshotTest "\(objectClass=posixaccount\)" posixAccountList0


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
