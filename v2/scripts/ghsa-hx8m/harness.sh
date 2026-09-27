#!/usr/bin/env bash
# GHSA-hx8m-chmx-x2j3 harness.
#
# Question: in an LDAP-proxy deployment where a user holds a local record
# carrying otpsecret, is the second factor enforced for EVERY spelling of that
# user's bind DN - or can a client pick a spelling the proxy cannot resolve but
# the upstream server can, and bind with the password alone?
#
# Two topologies, because the two bypasses need different upstream naming:
#   A  upstream and proxy both name users by cn  -> exercises the UPN/e-mail DN
#   B  upstream names by uid, proxy keeps the default "cn,uid"
#      -> exercises a DN using the second nameformat element
#
# Usage: harness.sh <glauth-binary>
set -uo pipefail
BIN="$1"; D="$(cd "$(dirname "$0")" && pwd)"
SECRET=3hnvnk4ycv44glzigd6s25j4dougs3rk
PASS=mysecret
pass=0; fail=0; invalid=0

cleanup() { kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

wait_port() {
  for _ in $(seq 100); do
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && { exec 3>&-; return 0; }
    sleep 0.1
  done
  return 1
}

# A bind is denied iff the server rejects the BIND itself. Post-bind errors look
# different, and ldapwhoami cannot be used - glauth has no whoami extended op,
# so it reports Protocol error whether the bind succeeded or not.
# NB: capture, do not pipe. With pipefail, "| grep -q" makes a DETECTED denial
# look like a pipeline failure: grep exits early, ldapsearch dies of SIGPIPE
# (141), pipefail surfaces that 141, and every bind reads as success.
# Connectivity failure gets its own state so it can never read as success.
bind() { # <port> <binddn> <password> -> ok|deny|error
  local out
  out=$(ldapsearch -x -H "ldap://127.0.0.1:$1" -D "$2" -w "$3" \
          -b "dc=glauth,dc=com" "(cn=otpuser)" 2>&1)
  case "$out" in
    *"ldap_bind:"*)                     echo deny  ;;
    *"Can't contact"*|*ldap_sasl_bind*) echo error ;;
    *)                                  echo ok    ;;
  esac
}

try() { # <port> <label> <expect> <binddn> <password>
  local got; got=$(bind "$1" "$4" "$5")
  if [ "$got" = "$3" ]; then
    printf '  PASS  %-50s %s\n' "$2" "$got"; pass=$((pass+1))
  else
    printf '  FAIL  %-50s got=%s want=%s\n' "$2" "$got" "$3"; fail=$((fail+1))
  fi
}

start() { # <upstream cfg> <upstream port> <proxy cfg> <proxy port> <tag>
  "$BIN" -c "$1" >"$D/up-$5.log" 2>&1 &
  wait_port "$2" || { echo "FATAL: upstream $5 never listened"; tail -5 "$D/up-$5.log"; exit 2; }
  "$BIN" -c "$3" >"$D/px-$5.log" 2>&1 &
  wait_port "$4" || { echo "FATAL: proxy $5 never listened"; tail -5 "$D/px-$5.log"; exit 2; }
}

OTP=$(oathtool --totp -b "$SECRET")
CN="cn=otpuser,ou=superheros,dc=glauth,dc=com"
UID_DN="uid=otpuser,ou=superheros,dc=glauth,dc=com"

echo "=== topology A: upstream and proxy both name by cn (port 3894) ==="
start "$D/upstream.cfg" 3893 "$D/proxy.cfg" 3894 A
# Self-check: if the canonical password+OTP bind is refused, every "deny" below
# is meaningless - the harness would report success while proving nothing.
if [ "$(bind 3894 "$CN" "${PASS}${OTP}")" != "ok" ]; then
  echo "  FATAL: harness invalid - canonical password+valid OTP was denied"
  tail -12 "$D/px-A.log"; invalid=1
else
  try 3894 "control: cn= + password + valid OTP"   ok   "$CN" "${PASS}${OTP}"
  try 3894 "control: cn= + password only"          deny "$CN" "$PASS"
  try 3894 "control: cn= + password + wrong OTP"   deny "$CN" "${PASS}000000"
  try 3894 "BYPASS: UPN + password only"           deny "otpuser@glauth.com" "$PASS"
  try 3894 "BYPASS: UPN uppercased + password"     deny "OTPUSER@GLAUTH.COM" "$PASS"
  try 3894 "negative: cn= + wrong password + OTP"  deny "$CN" "wrongpw${OTP}"
  try 3894 "negative: UPN + wrong password"        deny "otpuser@glauth.com" "wrongpw"
  try 3894 "negative: unknown user + password"     deny "nobody@glauth.com" "$PASS"
fi

echo
echo "=== topology B: upstream names by uid, proxy default cn,uid (port 3896) ==="
start "$D/upstreamB.cfg" 3895 "$D/proxyB.cfg" 3896 B
if [ "$(bind 3896 "$UID_DN" "${PASS}${OTP}")" != "ok" ]; then
  echo "  NOTE: uid= + password + valid OTP denied here."
  echo "        Expected on a pre-fix binary: the proxy cannot resolve uid= so it"
  echo "        waives OTP, then forwards password+OTP as the password upstream."
  try 3896 "BYPASS: uid= + password only"          deny "$UID_DN" "$PASS"
  try 3896 "negative: uid= + wrong password"       deny "$UID_DN" "wrongpw"
else
  try 3896 "control: uid= + password + valid OTP"  ok   "$UID_DN" "${PASS}${OTP}"
  try 3896 "BYPASS: uid= + password only"          deny "$UID_DN" "$PASS"
  try 3896 "negative: uid= + wrong password"       deny "$UID_DN" "wrongpw"
fi

echo
echo "=== topology C: pure proxy, no local records (port 3898) ==="
start "$D/upstreamC.cfg" 3897 "$D/proxyC.cfg" 3898 C
# The waiver this deployment depends on: no local record means no second factor
# of ours to enforce, so the password alone must still bind.
try 3898 "fail-open kept: no local record + password"  ok   "$CN" "$PASS"
try 3898 "still authenticated upstream: wrong password" deny "$CN" "wrongpw"

echo
echo "  $pass passed, $fail failed"
[ "$invalid" -eq 0 ] && [ "$fail" -eq 0 ]
