# omni-enrollment — endpoint agent

`omni-enrollment` is the small native client that enrolls a Linux machine with
Omni Identity and keeps its device credential fresh. It never sees or stores a
user's password, LDAP password, TOTP secret, or passkey; the user authenticates
in their own browser and the agent only ever proves possession of the device
key it generated locally. Protocol details: [DEVICE-IDENTITY-ARCHITECTURE.md](DEVICE-IDENTITY-ARCHITECTURE.md);
what it does and does not protect against: [DEVICE-THREAT-MODEL.md](DEVICE-THREAT-MODEL.md).

## Build

Pure Go, no CGO, cross-compiles from any host:

```bash
make build-enrollment ARCH=arm64      # → omni-enrollment-linux-arm64
```

## Install (Linux)

```bash
sudo install -m 0755 omni-enrollment-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') /usr/local/bin/omni-enrollment
sudo install -d -m 0755 /etc/omni-enrollment
sudo install -m 0644 endpoint/systemd/config.example.yaml /etc/omni-enrollment/config.yaml   # set issuer:
sudo install -m 0644 endpoint/systemd/omni-enrollment.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Enroll

```
$ sudo omni-enrollment enroll --issuer https://identity.example
Generating device identity...

Device:
    name:        omni-laptop
    hostname:    omni-laptop
    platform:    linux (arm64)
    fingerprint: 8fJc…

Authenticate with Omni Identity:

    https://identity.example/device?user_code=BCDF-GHJK

    (or open https://identity.example/device and enter the code BCDF-GHJK)

Waiting for approval....
Enrolled as alice (device id 4c1e…).
```

Open the link on any browser, sign in normally (password, LDAP, TOTP, passkey),
check that the page names the device you are looking at, and press **Enroll
device**. The device then appears under **My Devices**.

Then start the daemon:

```bash
sudo systemctl enable --now omni-enrollment
```

`sudo` is required because the key lives in `/var/lib/omni-enrollment`
(`0700 root`); see *Files* below. For private-network testing against an
`http://` issuer add `--allow-insecure-http` (never in production).

## Commands

| Command | What it does |
|---|---|
| `enroll --issuer URL [--name N]` | Generate the key and run the enrollment ceremony. Refuses if already enrolled. |
| `status [--json]` | Show the enrollment record and the daemon's last renewal / error. Works offline. |
| `renew` | Obtain one device token now (RFC 7523 jwt-bearer grant). Exit 1 if Omni refuses (revoked) or is unreachable. |
| `rotate-key` | Generate a new key, register it (signed by both old and new key), then commit it locally. |
| `unenroll` | Revoke the device server-side (best effort) and delete the local key and record. |
| `daemon` | Renewal loop used by the systemd unit. |

Configuration precedence: flag > `OMNI_ENROLLMENT_*` environment > `/etc/omni-enrollment/config.yaml`.

## Files

| Path | Mode | Contents |
|---|---|---|
| `/var/lib/omni-enrollment/device.key` | `0600 root` | Ed25519 private key (PKCS#8 PEM). **Never leaves the machine.** |
| `/var/lib/omni-enrollment/device.json` | `0600 root` | device id, fingerprint, issuer, owner, last known status. No secrets. |
| `/run/omni-enrollment/status.json` | `0644` | daemon view: status, reachability, last renewal, token expiry, last error. No tokens. |

The agent refuses to load a key file that is readable by other users.

## What the daemon does (and does not do)

Every half token lifetime (default 30 min; at least every minute) it performs
the jwt-bearer grant. Success → `status: active`. Omni unreachable → keeps the
last known status, backs off up to 15 min, `issuer_reachable: false`. Omni
answered but refused (device revoked, owner disabled) → `status: revoked`,
re-checked every 15 min; the operator must re-enroll.

It holds the device token in memory only. It does not run remote commands,
enforce policy, collect inventory, or talk to anything but the configured
issuer. The Linux login integration (Phase 6) will read `status.json` and talk
to the daemon over a root-only Unix socket; that is the extent of its local
surface.

## Revocation from the user's side

**My Devices → Revoke** (or an admin under **Devices**). The next renewal fails
and the daemon records `revoked`. Any device-bound refresh tokens are revoked
immediately; outstanding device tokens expire within `device_token_ttl`
(default 1 h). A revoked key can never be re-enrolled; run `unenroll` then
`enroll` to start over with a new key.

## Hardware-backed keys (future)

The key sits behind the `enrollment.Signer` interface (sign, public JWK,
fingerprint). A TPM 2.0 or Secure Enclave implementation only has to satisfy
that interface and register a signing method with the JWT library; the
protocol accepts `ES256`/`RS256` keys already.
