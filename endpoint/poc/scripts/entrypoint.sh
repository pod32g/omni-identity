#!/bin/bash
# Container entrypoint: set the break-glass password from the environment
# (never baked into the image) and run sshd in the foreground.
set -euo pipefail
: "${RECOVERY_PASSWORD:?RECOVERY_PASSWORD must be set}"
echo "omni-recovery:${RECOVERY_PASSWORD}" | chpasswd
exec /usr/sbin/sshd -D -e
