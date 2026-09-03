#!/bin/bash
# Enrolls a second device identity through the graphical page, exactly as a
# desktop user would, with curl standing in for the browser: the bare command
# (the GUI is the default) prints a one-time URL; visiting it sets the session
# cookie; /enroll needs the CSRF header; /status carries the user code, which
# alice approves through the real /device pages; then the device is unenrolled
# from the same page. Foreign Host and header-less POSTs must be refused.
set -euo pipefail
issuer="${OMNI_ISSUER:-http://omni:8080}"
base=http://127.0.0.1:18096
st=/tmp/gui-state; rt=/tmp/gui-run; log=/tmp/gui.log
rm -rf "$st" "$rt"
omni-enrollment --no-open --listen 127.0.0.1:18096 --exit-when-idle 2m \
  --state-dir "$st" --runtime-dir "$rt" --issuer "$issuer" --allow-insecure-http --name omni-gui >"$log" 2>&1 &
gui=$!
jar="$(mktemp)"
trap 'rm -f "$jar"; kill $gui 2>/dev/null || true' EXIT
url=""
for i in $(seq 1 20); do
  url="$(grep -o 'http://127.0.0.1:18096/?t=[A-Za-z0-9_-]*' "$log" | head -1 || true)"
  [[ -n "$url" ]] && break; sleep 1
done
[[ -n "$url" ]] || { cat "$log"; exit 1; }
token="${url##*t=}"

# Guards: a foreign Host is refused; without the cookie nothing is served.
curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "$url" | grep -q '^403$' || { echo "foreign Host accepted"; exit 1; }
curl -s -o /dev/null -w '%{http_code}' "$base/status" | grep -q '^403$' || { echo "status served without the session cookie"; exit 1; }
# The one-time URL becomes the session cookie.
curl -fsS -c "$jar" -b "$jar" -L -o /dev/null "$url"
# A POST with the cookie but without the CSRF header is refused.
curl -s -o /dev/null -w '%{http_code}' -b "$jar" -X POST "$base/cancel" | grep -q '^403$' || { echo "POST accepted without CSRF header"; exit 1; }

curl -fsS -b "$jar" -H "X-Omni-GUI: $token" --data-urlencode "issuer=$issuer" --data-urlencode "name=omni-gui" \
  --data-urlencode "key_backend=file" --data-urlencode "allow_insecure_http=on" "$base/enroll" >/tmp/gui-enroll.json
code="$(sed -n 's/.*"code":"\([^"]*\)".*/\1/p' /tmp/gui-enroll.json)"
[[ -n "$code" ]] || { cat /tmp/gui-enroll.json; cat "$log"; exit 1; }
curl -fsS -b "$jar" -o /tmp/gui-qr.svg "$base/qr.svg" && grep -q '<svg' /tmp/gui-qr.svg
echo "    GUI enrollment code: $code (QR served; alice approves it on her phone)"
/poc/approve.sh "$code"
status=""
for i in $(seq 1 30); do
  status="$(curl -fsS -b "$jar" "$base/status")"
  grep -q '"Phase":"done"' <<<"$status" && break; sleep 1
done
grep -q '"Phase":"done"' <<<"$status" || { echo "$status"; cat "$log"; exit 1; }
grep -q '"Enrolled":true' <<<"$status" || { echo "$status"; exit 1; }
grep -q 'Enrolled as alice' <<<"$status" || { echo "$status"; exit 1; }
echo "    GUI: $(sed -n 's/.*"Message":"\([^"]*\)".*/\1/p' <<<"$status")"
test -f "$st/device.key" && test -f "$st/device.json"

curl -fsS -b "$jar" -H "X-Omni-GUI: $token" -X POST "$base/unenroll" >/dev/null
curl -fsS -b "$jar" "$base/status" | grep -q '"Enrolled":false' || { echo "still enrolled after unenroll"; exit 1; }
test ! -e "$st/device.key"
echo "    GUI: device unenrolled, key removed"
