#!/bin/bash
# Linux login proof of concept (docs/LINUX-LOGIN-POC.md). Runs Omni Identity
# natively on this host and a disposable Debian endpoint as a Docker container,
# enrolls the endpoint, logs in through SSH/PAM online, cuts the container's
# network and logs in offline, exercises the break-glass account, reconnects,
# refreshes trust, revokes the device, and shows revocation taking effect.
#
#   endpoint/poc/run-poc.sh          # run everything, clean up at the end
#   endpoint/poc/run-poc.sh --keep   # leave containers running for inspection
#   POC_BASE=debian:stable-slim endpoint/poc/run-poc.sh   # other endpoint base image
#   OMNI_POC_IMAGE=omni-identity:latest endpoint/poc/run-poc.sh
#       # run the throwaway Omni as a container from that image instead of a
#       # host binary (what the self-hosted CI runner does after a deploy)
#
# Two ways to run the throwaway Omni Identity:
#   native    — built with the host Go toolchain and bound to loopback (or the
#               Docker bridge address on Linux); the endpoint reaches it via
#               host.docker.internal. The developer default.
#   container — from OMNI_POC_IMAGE on the private PoC network with alias
#               "omni", published on 127.0.0.1 only. Chosen automatically on a
#               Linux host without Go. Nothing listens beyond loopback.
set -euo pipefail
cd "$(dirname "$0")/../.."

KEEP=0; [[ "${1:-}" == "--keep" ]] && KEEP=1
NET=omni-poc; EP=omni-poc-endpoint; OMNI=omni-poc-identity
PORT="${OMNI_POC_PORT:-18080}"
WORK="$(mktemp -d)"
OMNI_PID=""
OMNI_IMAGE="${OMNI_POC_IMAGE:-}"
if [[ -z "$OMNI_IMAGE" && "$(uname -s)" == Linux ]] && ! command -v go >/dev/null 2>&1; then
  OMNI_IMAGE=omni-identity:latest
fi
if [[ -z "$OMNI_IMAGE" ]] && ! command -v go >/dev/null 2>&1; then
  echo "no Go toolchain: install Go, or set OMNI_POC_IMAGE to run Omni from an image" >&2; exit 1
fi
SETUP_TOKEN="$(openssl rand -hex 16)"
ADMIN_PW="Adm1n-$(openssl rand -hex 6)"
ALICE_PW="Al1ce-$(openssl rand -hex 6)"
BOB_PW="B0b-$(openssl rand -hex 6)"
RECOVERY_PW="Rec0very-$(openssl rand -hex 6)"
LOCAL_PW="local-offline-pw-$(openssl rand -hex 3)"
ARCH="$(docker version --format '{{.Server.Arch}}')"
POC_BASE="${POC_BASE:-ubuntu:24.04}"
# Where the throwaway Omni listens (native mode). On Linux the endpoint reaches
# the host through the Docker bridge gateway (what --add-host host-gateway
# resolves to), so bind to exactly that address — never 0.0.0.0, the harness
# may run on a host that also serves production. Docker Desktop routes
# host.docker.internal to loopback, so 127.0.0.1 suffices on macOS.
HOST_BIND=127.0.0.1
if [[ -z "$OMNI_IMAGE" && "$(uname -s)" == Linux ]]; then
  HOST_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi
ISSUER_LOCAL="http://${HOST_BIND}:${PORT}"          # how this script reaches Omni
ISSUER="http://host.docker.internal:${PORT}"       # how the endpoint reaches Omni (= public URL)
if [[ -n "$OMNI_IMAGE" ]]; then
  ISSUER="http://omni:8080"
fi
if (echo >"/dev/tcp/${HOST_BIND}/${PORT}") 2>/dev/null; then
  echo "port ${PORT} on ${HOST_BIND} is already in use; set OMNI_POC_PORT" >&2; exit 1
fi

# Build Go binaries with the host toolchain when present, otherwise inside
# the pinned Go builder image (self-hosted runners may have Docker but no Go).
GO_IMAGE="$(sed -nE 's/^FROM (golang:[^ ]+) AS build/\1/p' Dockerfile | head -1)"
GO_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/omni-poc-go"
gobuild() {  # gobuild <output> <package> [KEY=VAL...]
  local out="$1" pkg="$2"; shift 2
  if command -v go >/dev/null 2>&1; then
    env "$@" go build -o "$out" "$pkg"
    return
  fi
  # Builder container runs as the invoking user so nothing root-owned lands in
  # the checkout or the work dir; module/build caches persist under the
  # user's cache dir between runs.
  mkdir -p "$GO_CACHE_DIR/mod" "$GO_CACHE_DIR/build"
  local envs=()
  for kv in "$@"; do envs+=(-e "$kv"); done
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD:/src" -w /src -v "$WORK:$WORK" \
    -v "$GO_CACHE_DIR/mod:/tmp/gomod" -v "$GO_CACHE_DIR/build:/tmp/gocache" \
    -e HOME=/tmp -e GOMODCACHE=/tmp/gomod -e GOCACHE=/tmp/gocache -e GOFLAGS=-buildvcs=false \
    ${envs[@]+"${envs[@]}"} "$GO_IMAGE" go build -o "$out" "$pkg"
}

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32m    PASS: %s\033[0m\n' "$*"; }
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo; echo "!!! PoC failed (exit $rc). Diagnostics:"
    docker logs "$EP" 2>&1 | tail -20 || true
    docker exec "$EP" tail -20 /var/log/omni-enrollment.log 2>/dev/null || true
    if [[ -n "$OMNI_IMAGE" ]]; then docker logs "$OMNI" 2>&1 | tail -5 || true; else tail -5 "$WORK/omni.log" 2>/dev/null || true; fi
  fi
  if [[ $KEEP -eq 1 ]]; then
    echo; echo "kept: docker exec -it $EP bash   |   Omni at $ISSUER_LOCAL (admin/$ADMIN_PW, alice/$ALICE_PW)"; return
  fi
  docker rm -fv "$EP" "$OMNI" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [[ -n "$OMNI_PID" ]] && kill "$OMNI_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Admin-side helpers (this script plays the administrator and, for approvals
# during enrollment, alice on her phone).
JAR="$(mktemp)"
csrf() { awk '$6=="omni_csrf"{print $7}' "$JAR"; }
post() { curl -fsS -b "$JAR" -c "$JAR" -o /dev/null --data-urlencode "csrf_token=$(csrf)" "$@"; }

step "Building the endpoint image${OMNI_IMAGE:+ (Omni from image $OMNI_IMAGE)}"
[[ -n "$OMNI_IMAGE" ]] || gobuild "$WORK/omni-identity" ./cmd/omni-identity
gobuild "omni-enrollment-linux-$ARCH" ./cmd/omni-enrollment CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH"
docker build -q --build-arg BASE="$POC_BASE" -f endpoint/poc/Dockerfile.endpoint -t omni-endpoint:poc . >/dev/null
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -fv "$EP" "$OMNI" >/dev/null 2>&1 || true

step "Starting Omni Identity on $ISSUER_LOCAL (public URL $ISSUER)"
if [[ -n "$OMNI_IMAGE" ]]; then
  docker run -d --name "$OMNI" --network "$NET" --network-alias omni -p "127.0.0.1:${PORT}:8080" \
    -e OMNI_SERVER_HOST=0.0.0.0 -e OMNI_SERVER_PORT=8080 -e OMNI_SERVER_PUBLIC_URL="$ISSUER" \
    -e OMNI_ALLOW_INSECURE_HTTP=true -e OMNI_COOKIES_SECURE=false -e OMNI_SETUP_TOKEN="$SETUP_TOKEN" \
    -e OMNI_DATABASE_PATH=/data/omni.db "$OMNI_IMAGE" >/dev/null
else
  OMNI_SERVER_HOST="$HOST_BIND" OMNI_SERVER_PORT="$PORT" OMNI_SERVER_PUBLIC_URL="$ISSUER" \
    OMNI_ALLOW_INSECURE_HTTP=true OMNI_COOKIES_SECURE=false OMNI_SETUP_TOKEN="$SETUP_TOKEN" \
    OMNI_DATABASE_PATH="$WORK/omni.db" "$WORK/omni-identity" serve -config /dev/null > "$WORK/omni.log" 2>&1 &
  OMNI_PID=$!
fi
for i in $(seq 1 30); do curl -fsS "$ISSUER_LOCAL/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$ISSUER_LOCAL/healthz" >/dev/null

step "Bootstrapping admin and user alice"
curl -fsS -c "$JAR" -o /dev/null "$ISSUER_LOCAL/setup"
post --data-urlencode "setup_token=$SETUP_TOKEN" --data-urlencode "username=admin" \
     --data-urlencode "email=admin@example.com" --data-urlencode "password=$ADMIN_PW" "$ISSUER_LOCAL/setup"
post --data-urlencode "username=alice" --data-urlencode "email=alice@example.com" \
     --data-urlencode "password=$ALICE_PW" "$ISSUER_LOCAL/admin/users"
post --data-urlencode "username=bob" --data-urlencode "email=bob@example.com" \
     --data-urlencode "password=$BOB_PW" "$ISSUER_LOCAL/admin/users"
# A local application the token broker may issue tokens for.
post --data-urlencode "name=Omni Metrics" --data-urlencode "client_id=omni-metrics" --data-urlencode "type=confidential" \
     --data-urlencode "redirect_uris=https://metrics.example/cb" --data-urlencode "scopes=openid email profile" "$ISSUER_LOCAL/admin/clients"
pass "admin + alice + bob + omni-metrics client created"

step "Starting the endpoint container ($POC_BASE, sshd + pam_omni)"
docker run -d --name "$EP" --network "$NET" --add-host=host.docker.internal:host-gateway \
  -e RECOVERY_PASSWORD="$RECOVERY_PW" \
  -e OMNI_ISSUER="$ISSUER" -e OMNI_USER=alice -e OMNI_PASSWORD="$ALICE_PW" omni-endpoint:poc >/dev/null
sleep 2

step "Enrolling the endpoint (device key generated locally)"
docker exec "$EP" sh -c "omni-enrollment enroll --issuer $ISSUER --allow-insecure-http --name omni-vm > /tmp/enroll.log 2>&1 &"
for i in $(seq 1 30); do
  code="$(docker exec "$EP" sh -c "grep -o 'user_code=[A-Z-]*' /tmp/enroll.log | head -1 | cut -d= -f2" || true)"
  [[ -n "$code" ]] && break; sleep 1
done
[[ -n "$code" ]] || { docker exec "$EP" cat /tmp/enroll.log; exit 1; }
echo "    enrollment code: $code (alice approves it in her browser)"
docker exec "$EP" /poc/approve.sh "$code"
for i in $(seq 1 20); do docker exec "$EP" grep -q "Enrolled as alice" /tmp/enroll.log 2>/dev/null && break; sleep 1; done
docker exec "$EP" cat /tmp/enroll.log
docker exec "$EP" omni-enrollment status
DEVICE_ID="$(docker exec "$EP" omni-enrollment status --json | sed -n 's/.*"device_id":"\([^"]*\)".*/\1/p' | head -1)"
pass "device $DEVICE_ID enrolled to alice; private key stayed in /var/lib/omni-enrollment"

step "Starting the enrollment daemon (renewal + PAM socket)"
docker exec -d -e OMNI_ENROLLMENT_BROKER_AUDIENCES=omni-metrics "$EP" sh -c "omni-enrollment daemon --refresh-interval 15s > /var/log/omni-enrollment.log 2>&1"
sleep 3
docker exec "$EP" test -S /run/omni-enrollment/pam.sock
docker exec "$EP" test -S /run/omni-enrollment/nss.sock
pass "daemon up, PAM and NSS sockets present"

step "Scenario 26-27: online SSH login as alice through Omni (device-bound device grant)"
docker exec "$EP" getent passwd alice   # identity served by libnss_omni (no /etc/passwd entry)
docker exec "$EP" grep -q '^alice:' /etc/passwd && { echo "alice must not be in /etc/passwd"; exit 1; }
docker exec "$EP" /poc/ssh-login.exp alice online "$LOCAL_PW"
docker exec "$EP" sh -c 'stat -c "%U %a %n" /home/alice'
pass "alice authenticated via Omni through PAM; identity via NSS; home created; local offline password set"

step "Local token broker: alice's own process gets an omni-metrics token; root and bob do not"
TOK="$(docker exec "$EP" su - alice -c 'omni-enrollment token --audience omni-metrics')"
payload="$(echo "$TOK" | cut -d. -f2 | tr '_-' '/+')"
pad=$(( (4 - ${#payload} % 4) % 4 )); while [ $pad -gt 0 ]; do payload="$payload="; pad=$((pad-1)); done
echo "$payload" | base64 -d | grep -q '"aud":"omni-metrics"' || { echo "token lacks the audience"; exit 1; }
echo "$payload" | base64 -d | grep -q '"act":{"sub":"' || { echo "token lacks the act claim"; exit 1; }
docker exec "$EP" sh -c 'omni-enrollment token --audience omni-metrics 2>&1 | grep -q "root" || { echo "root got a token"; exit 1; }'
(docker exec "$EP" su - alice -c 'omni-enrollment token --audience jellyfin' 2>&1 || true) | grep -q "not allowed" || { echo "disallowed audience issued"; exit 1; }
pass "broker issued an audience-bound token to alice only (RFC 8693 with the device as actor)"

step "Scenario 26 (non-owner): bob's first ever SSH login, resolved through NSS + Omni lookup"
docker exec "$EP" sh -c 'getent passwd bob | grep -q "^bob:" && ! grep -q "^bob:" /etc/passwd'
docker exec -e OMNI_USER=bob -e OMNI_PASSWORD="$BOB_PW" "$EP" /poc/ssh-login.exp bob online "$LOCAL_PW"
pass "bob (never seen on this machine) logged in over SSH via NSS lookup and device-bound login"

step "Scenario 28-31: network disconnected -> offline login with the local password"
docker network disconnect "$NET" "$EP"
docker exec "$EP" sh -c "curl -s -m 3 $ISSUER/healthz >/dev/null 2>&1 && exit 1 || true"
docker exec "$EP" /poc/ssh-login.exp alice offline "$LOCAL_PW"
pass "offline login OK while Omni is unreachable"
docker exec "$EP" /poc/ssh-login.exp alice expect-fail "wrong-password"
pass "wrong local password refused"

step "Scenario 32: break-glass omni-recovery works without Omni, network, or the daemon"
docker exec "$EP" pkill -f 'omni-enrollment daemon' || true
docker exec "$EP" /poc/recovery-login.exp "$RECOVERY_PW"
docker exec -d -e OMNI_ENROLLMENT_BROKER_AUDIENCES=omni-metrics "$EP" sh -c "omni-enrollment daemon --refresh-interval 15s >> /var/log/omni-enrollment.log 2>&1"
pass "omni-recovery logged in over SSH via pam_unix and used sudo, with daemon stopped and network down"

step "Scenario 33-34: reconnect -> device trust refresh"
docker network connect "$NET" "$EP"
for i in $(seq 1 40); do docker exec "$EP" grep -q "trust refreshed for alice" /var/log/omni-enrollment.log 2>/dev/null && break; sleep 1; done
docker exec "$EP" grep -E "renewed|trust refreshed" /var/log/omni-enrollment.log | tail -3
pass "device token renewed and alice's trust refreshed after reconnect"

step "Scenario 35: alice revokes the device in Omni (My Devices -> Revoke)"
ALICE_JAR="$(mktemp)"
curl -fsS -c "$ALICE_JAR" -o /dev/null "$ISSUER_LOCAL/login"
acsrf="$(awk '$6=="omni_csrf"{print $7}' "$ALICE_JAR")"
curl -fsS -b "$ALICE_JAR" -c "$ALICE_JAR" -o /dev/null --data-urlencode "csrf_token=$acsrf" \
  --data-urlencode "username=alice" --data-urlencode "password=$ALICE_PW" "$ISSUER_LOCAL/login"
curl -fsS -b "$ALICE_JAR" -c "$ALICE_JAR" -o /dev/null --data-urlencode "csrf_token=$acsrf" \
  "$ISSUER_LOCAL/account/devices/$DEVICE_ID/revoke"
for i in $(seq 1 40); do docker exec "$EP" grep -q "refused for alice" /var/log/omni-enrollment.log 2>/dev/null && break; sleep 1; done
docker exec "$EP" grep -E "refused" /var/log/omni-enrollment.log | tail -2
docker exec "$EP" /poc/ssh-login.exp alice expect-fail ""
pass "after revocation: online login refused and offline cache invalidated"
docker network disconnect "$NET" "$EP"
docker exec "$EP" /poc/ssh-login.exp alice expect-fail "$LOCAL_PW"
docker exec "$EP" /poc/recovery-login.exp "$RECOVERY_PW"
docker network connect "$NET" "$EP"
pass "revoked device stays locked out offline; break-glass still works"

printf '\n\033[1;32mAll PoC scenarios passed.\033[0m\n'
