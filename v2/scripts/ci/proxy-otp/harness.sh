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
BIN="${1:-bin/glauth}"; D="$(cd "$(dirname "$0")" && pwd)"

for tool in ldapsearch oathtool; do
  command -v "$tool" >/dev/null || { echo "- skipping proxy OTP tests: $tool not installed"; exit 0; }
done
[ -x "$BIN" ] || { echo "- skipping proxy OTP tests: no binary at $BIN"; exit 0; }
SECRET=3hnvnk4ycv44glzigd6s25j4dougs3rk
PASS=mysecret
pass=0; fail=0; invalid=0

# Logs go to a temporary directory so a run never touches the checkout.
LOGS=$(mktemp -d) || { echo "FATAL: could not create a temporary directory for logs"; exit 2; }
cleanup() { kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; rm -rf "$LOGS"; }
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
  "$BIN" -c "$1" >"$LOGS/up-$5.log" 2>&1 &
  wait_port "$2" || { echo "FATAL: upstream $5 never listened"; tail -5 "$LOGS/up-$5.log"; exit 2; }
  "$BIN" -c "$3" >"$LOGS/px-$5.log" 2>&1 &
  wait_port "$4" || { echo "FATAL: proxy $5 never listened"; tail -5 "$LOGS/px-$5.log"; exit 2; }
}

OTP=$(oathtool --totp -b "$SECRET")
CN="cn=otpuser,ou=superheros,dc=glauth,dc=com"
UID_DN="uid=otpuser,ou=superheros,dc=glauth,dc=com"

echo "=== topology A: upstream and proxy both name by cn (port 13902) ==="
start "$D/upstream.cfg" 13901 "$D/proxy.cfg" 13902 A
# Self-check: if the canonical password+OTP bind is refused, every "deny" below
# is meaningless - the harness would report success while proving nothing.
if [ "$(bind 13902 "$CN" "${PASS}${OTP}")" != "ok" ]; then
  echo "  FATAL: harness invalid - canonical password+valid OTP was denied"
  tail -12 "$LOGS/px-A.log"; invalid=1
else
  try 13902 "control: cn= + password + valid OTP"   ok   "$CN" "${PASS}${OTP}"
  try 13902 "control: cn= + password only"          deny "$CN" "$PASS"
  try 13902 "control: cn= + password + wrong OTP"   deny "$CN" "${PASS}000000"
  try 13902 "BYPASS: UPN + password only"           deny "otpuser@glauth.com" "$PASS"
  try 13902 "BYPASS: UPN uppercased + password"     deny "OTPUSER@GLAUTH.COM" "$PASS"
  try 13902 "negative: cn= + wrong password + OTP"  deny "$CN" "wrongpw${OTP}"
  try 13902 "negative: UPN + wrong password"        deny "otpuser@glauth.com" "wrongpw"
  try 13902 "negative: unknown user + password"     deny "nobody@glauth.com" "$PASS"
fi

echo
echo "=== topology B: upstream names by uid, proxy default cn,uid (port 13904) ==="
start "$D/upstreamB.cfg" 13903 "$D/proxyB.cfg" 13904 B
if [ "$(bind 13904 "$UID_DN" "${PASS}${OTP}")" != "ok" ]; then
  echo "  NOTE: uid= + password + valid OTP denied here."
  echo "        Expected on a pre-fix binary: the proxy cannot resolve uid= so it"
  echo "        waives OTP, then forwards password+OTP as the password upstream."
  try 13904 "BYPASS: uid= + password only"          deny "$UID_DN" "$PASS"
  try 13904 "negative: uid= + wrong password"       deny "$UID_DN" "wrongpw"
else
  try 13904 "control: uid= + password + valid OTP"  ok   "$UID_DN" "${PASS}${OTP}"
  try 13904 "BYPASS: uid= + password only"          deny "$UID_DN" "$PASS"
  try 13904 "negative: uid= + wrong password"       deny "$UID_DN" "wrongpw"
fi

echo
echo "=== topology C: pure proxy, no local records (port 13906) ==="
start "$D/upstreamC.cfg" 13905 "$D/proxyC.cfg" 13906 C
# The waiver this deployment depends on: no local record means no second factor
# of ours to enforce, so the password alone must still bind.
try 13906 "fail-open kept: no local record + password"  ok   "$CN" "$PASS"
try 13906 "still authenticated upstream: wrong password" deny "$CN" "wrongpw"

echo
echo "=== topology D: proxy overlay marks a user disabled (GHSA-2wj6, port 13908) ==="
start "$D/upstreamD.cfg" 13907 "$D/proxyD.cfg" 13908 D
GOOD="cn=gooduser,ou=superheros,dc=glauth,dc=com"
SVC="cn=svcuser,ou=superheros,dc=glauth,dc=com"
# Self-check: an enabled overlay user must bind with the upstream password,
# otherwise every "deny" below proves nothing (the proxy path would be dead).
if [ "$(bind 13908 "$GOOD" "$PASS")" != "ok" ]; then
  echo "  FATAL: harness invalid - enabled overlay user denied with correct password"
  tail -12 "$LOGS/px-D.log"; invalid=1
else
  try 13908 "control: enabled overlay user + password"   ok   "$GOOD" "$PASS"
  try 13908 "BYPASS: disabled overlay user + password"   deny "$SVC"  "$PASS"
  try 13908 "negative: disabled overlay user + wrong pw"  deny "$SVC"  "wrongpw"
fi

echo
echo "  $pass passed, $fail failed"
[ "$invalid" -eq 0 ] && [ "$fail" -eq 0 ]
