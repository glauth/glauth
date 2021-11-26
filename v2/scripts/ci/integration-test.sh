#!/bin/bash

export CLEANUP="$1"

## Main Methods


# Dep check

command -v oathtool ;
if [[ "$?" = "1" ]] ; then
  echo "Please install oathtool or add it to \$PATH before continuing."
  exit 1;
fi

# Get the git working directory base if CI build dir isn't set
if [[ "$CI_BUILD_DIR" == "" ]] ; then
  export CI_BUILD_DIR="$(git rev-parse --show-toplevel)/v2"
fi

# Fix semantic version naming
echo "Fixing CI_BUILD_DIR"
[[ $CI_BUILD_DIR == */v2 ]] || export CI_BUILD_DIR=$CI_BUILD_DIR/v2

# This script requires that "$CI_BUILD_DIR" is set to the repo root

# Ensure ldap utils are installed (for example - when running this outside of CI)
if [[ ! `which ldapsearch` ]]; then
	sudo apt-get -qq update && sudo apt-get -qq install -y ldap-utils || exit 1;
fi

# Display version string
echo "";
echo ""
echo "Version string of tested binary:"
"$CI_BUILD_DIR/bin/linuxamd64/glauth" --version
echo ""

# Start in background, capture PID
"$CI_BUILD_DIR/bin/linuxamd64/glauth" -c "$CI_BUILD_DIR/scripts/ci/test-config.cfg" &> /dev/null &

# Use this instead to see glauth logs while running
# "$CI_BUILD_DIR/bin/linuxamd64/glauth" -c "$CI_BUILD_DIR/scripts/ci/test-config.cfg" &
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

# Used for OTP testing
# Arguments:
#    $1 - Full Bind DN
#    $2 - Full Bind PW
#    $3 - query to run
#    $4 - test name
function bindTest() {
  ldapsearch -LLL \
    -H ldap://localhost:3893 \
    -D "$1" \
    -w "$2" \
    -x -bdc=glauth,dc=com \
    "$3" > /dev/null

  exitCode="$?"

  if [[ "$exitCode" = "0" ]] ; then
    echo "  - PASS : Bind test '$4'";
  else
    echo "  - FAIL : Bind test '$4'";
    FAIL="1"
  fi


}

# Arguments:
#    $1 - query
#    $2 - name of snapshot
function snapshotTest() {

  goodResults="$CI_BUILD_DIR/scripts/ci/good-results"
  testResults="$CI_BUILD_DIR/scripts/ci/test-results"

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


    # Handle the first-run case, saving the test results
    if [ ! -f "$goodResults/$2" ]; then
      echo "  - FIRST RUN - SAVING SNAPSHOT, RUN AGAIN TO PASS : '$2'";

      # Copy the results to the goodResults dir, for future runs.
      cp "$testResults/$2" "$goodResults/$2";

      # NOTE: fail=1 must still be set, otherwise CI runs would succeed when they shouldn't
      FAIL="1"
    else

      THISFAIL="0"
      diff -u "$goodResults/$2" "$testResults/$2" || THISFAIL="1"


      if [[ "$CLEANUP" = "cleanup" ]] ; then
        rm -rf "$testResults"
      fi

    if [[ "$THISFAIL" = "0" ]] ; then
      echo "  - PASS : snapshot '$2'";
    else
      echo "  - FAIL : snapshot '$2'";
      FAIL="1"
    fi
  fi

}


echo "";
echo "";
echo "RUNNING TESTS:"
echo "";

#################
## TEST RUNS
#################

## Query output tests

# Regular single-user fetches
snapshotTest "cn=hackers" userFetchTest0
snapshotTest "cn=johndoe" userFetchTest1
snapshotTest "cn=serviceuser" userFetchTest2
snapshotTest "cn=jamesdoe" userFetchTest3
snapshotTest "cn=alexdoe" userFetchTest4

# Test result of fetching nonexistent users
snapshotTest "cn=fakeuser" userFetchNonexistentUser0
snapshotTest "cn=janedoe" userFetchNonexistentUser1

# List all posixgroups
snapshotTest "objectClass=posixgroup" posixGroupList0
snapshotTest "objectClass=posixaccount" posixAccountList0


## 2FA Bind Test
# Fetch the OTP for this moment
otpCode="$(oathtool --totp -b -d 6 '3hnvnk4ycv44glzigd6s25j4dougs3rk')"

pass="ThisAloneWontWork!"

# Try to bind with it
bindTest "cn=alexdoe,ou=superheros,dc=glauth,dc=com" \
  "$pass$otpCode" \
  "cn=alexdoe" \
  "OtpAlexDoe"

## App Password Bind Test

# Test the main pw
bindTest "cn=jackdoe,ou=superheros,dc=glauth,dc=com" \
  "dogood1" \
  "cn=jackdoe" \
  "AppPwNoOtp0"

# App passwords on user
bindTest "cn=jackdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw1" \
  "cn=jackdoe" \
  "AppPwNoOtp1"

bindTest "cn=jackdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw2" \
  "cn=jackdoe" \
  "AppPwNoOtp2"

bindTest "cn=jackdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw3" \
  "cn=jackdoe" \
  "AppPwNoOtp3"


####
# Test for a user who also uses OTP
####
otpCode="$(oathtool --totp -b -d 6 '3hnvnk4ycv44glzigd6s25j4dougs3rk')"

pass="dogood1"

# Test the main pw
bindTest "cn=sarahdoe,ou=superheros,dc=glauth,dc=com" \
  "$pass$otpCode" \
  "cn=sarahdoe" \
  "AppPwOtp0"

# App passwords on user
bindTest "cn=sarahdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw1" \
  "cn=sarahdoe" \
  "AppPwOtp1"

bindTest "cn=sarahdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw2" \
  "cn=sarahdoe" \
  "AppPwOtp2"

bindTest "cn=sarahdoe,ou=superheros,dc=glauth,dc=com" \
  "TestAppPw3" \
  "cn=sarahdoe" \
  "AppPwOtp3"

#############
## Cleanup
#############

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
