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
#
# Works on Docker Desktop (macOS) and on Linux hosts such as the GitHub
# runner: the endpoint reaches the host's Omni through host.docker.internal,
# mapped to the host gateway explicitly.
set -euo pipefail
cd "$(dirname "$0")/../.."

KEEP=0; [[ "${1:-}" == "--keep" ]] && KEEP=1
NET=omni-poc; EP=omni-poc-endpoint
PORT="${OMNI_POC_PORT:-18080}"
ISSUER_LOCAL="http://127.0.0.1:${PORT}"            # how this script reaches Omni
ISSUER="http://host.docker.internal:${PORT}"       # how the endpoint reaches Omni (= public URL)
WORK="$(mktemp -d)"
OMNI_PID=""
SETUP_TOKEN="$(openssl rand -hex 16)"
ADMIN_PW="Adm1n-$(openssl rand -hex 6)"
ALICE_PW="Al1ce-$(openssl rand -hex 6)"
RECOVERY_PW="Rec0very-$(openssl rand -hex 6)"
LOCAL_PW="local-offline-pw-$(openssl rand -hex 3)"
ARCH="$(docker version --format '{{.Server.Arch}}')"
POC_BASE="${POC_BASE:-ubuntu:24.04}"
# On Linux the container reaches the host via the docker0 gateway, so Omni
# must listen beyond loopback there; Docker Desktop routes host.docker.internal
# to loopback, so 127.0.0.1 suffices on macOS.
HOST_BIND=127.0.0.1; [[ "$(uname -s)" == Linux ]] && HOST_BIND=0.0.0.0

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32m    PASS: %s\033[0m\n' "$*"; }
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo; echo "!!! PoC failed (exit $rc). Diagnostics:"
    docker logs "$EP" 2>&1 | tail -20 || true
    docker exec "$EP" tail -20 /var/log/omni-enrollment.log 2>/dev/null || true
    tail -5 "$WORK/omni.log" 2>/dev/null || true
  fi
  if [[ $KEEP -eq 1 ]]; then
    echo; echo "kept: docker exec -it $EP bash   |   Omni (pid $OMNI_PID) at $ISSUER_LOCAL (admin/$ADMIN_PW, alice/$ALICE_PW), log $WORK/omni.log"; return
  fi
  docker rm -f "$EP" >/dev/null 2>&1 || true
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

step "Building omni-identity (host) and the endpoint image"
go build -o "$WORK/omni-identity" ./cmd/omni-identity
make -s build-enrollment ARCH="$ARCH"
docker build -q --build-arg BASE="$POC_BASE" -f endpoint/poc/Dockerfile.endpoint -t omni-endpoint:poc . >/dev/null

step "Starting Omni Identity on $ISSUER_LOCAL (public URL $ISSUER)"
OMNI_SERVER_HOST="$HOST_BIND" OMNI_SERVER_PORT="$PORT" OMNI_SERVER_PUBLIC_URL="$ISSUER" \
  OMNI_ALLOW_INSECURE_HTTP=true OMNI_COOKIES_SECURE=false OMNI_SETUP_TOKEN="$SETUP_TOKEN" \
  OMNI_DATABASE_PATH="$WORK/omni.db" "$WORK/omni-identity" serve -config /dev/null > "$WORK/omni.log" 2>&1 &
OMNI_PID=$!
for i in $(seq 1 30); do curl -fsS "$ISSUER_LOCAL/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$ISSUER_LOCAL/healthz" >/dev/null
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$EP" >/dev/null 2>&1 || true

step "Bootstrapping admin and user alice"
curl -fsS -c "$JAR" -o /dev/null "$ISSUER_LOCAL/setup"
post --data-urlencode "setup_token=$SETUP_TOKEN" --data-urlencode "username=admin" \
     --data-urlencode "email=admin@example.com" --data-urlencode "password=$ADMIN_PW" "$ISSUER_LOCAL/setup"
post --data-urlencode "username=alice" --data-urlencode "email=alice@example.com" \
     --data-urlencode "password=$ALICE_PW" "$ISSUER_LOCAL/admin/users"
pass "admin + alice created"

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
docker exec -d "$EP" sh -c "omni-enrollment daemon --refresh-interval 15s > /var/log/omni-enrollment.log 2>&1"
sleep 3
docker exec "$EP" test -S /run/omni-enrollment/pam.sock
pass "daemon up, /run/omni-enrollment/pam.sock present"

step "Scenario 26-27: online SSH login as alice through Omni (device-bound device grant)"
docker exec "$EP" getent passwd alice   # pre-provisioned at enrollment (sshd needs it before PAM)
docker exec "$EP" /poc/ssh-login.exp alice online "$LOCAL_PW"
pass "alice authenticated via Omni through PAM; local offline password set"

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
docker exec -d "$EP" sh -c "omni-enrollment daemon --refresh-interval 15s >> /var/log/omni-enrollment.log 2>&1"
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
