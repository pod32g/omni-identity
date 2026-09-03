#!/bin/bash
# Stand-in for "the user opens the link on their phone": signs in to Omni as
# $OMNI_USER and approves the given user code. Usage: approve.sh CODE
set -euo pipefail
code="$1"
issuer="${OMNI_ISSUER:-http://omni:8080}"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT
curl -fsS -c "$jar" -o /dev/null "$issuer/login"
csrf="$(awk '$6=="omni_csrf"{print $7}' "$jar")"
curl -fsS -b "$jar" -c "$jar" -o /dev/null \
  --data-urlencode "csrf_token=$csrf" --data-urlencode "username=$OMNI_USER" \
  --data-urlencode "password=$OMNI_PASSWORD" "$issuer/login"
# Look up, then confirm.
curl -fsS -b "$jar" -c "$jar" -o /dev/null \
  --data-urlencode "csrf_token=$csrf" --data-urlencode "user_code=$code" "$issuer/device"
out="$(curl -fsS -b "$jar" -c "$jar" \
  --data-urlencode "csrf_token=$csrf" --data-urlencode "user_code=$code" \
  --data-urlencode "action=allow" "$issuer/device/confirm")"
grep -q "Approved" <<<"$out" && echo "approved $code as $OMNI_USER"
