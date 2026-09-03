# omni-enrollment — endpoint agent

`omni-enrollment` is the small native client that enrolls a Linux machine with
Omni Identity and keeps its device credential fresh. It never sees or stores a
user's password, LDAP password, TOTP secret, or passkey; the user authenticates
in their own browser and the agent only ever proves possession of the device
key it generated locally. Protocol details: [DEVICE-IDENTITY-ARCHITECTURE.md](DEVICE-IDENTITY-ARCHITECTURE.md);
what it does and does not protect against: [DEVICE-THREAT-MODEL.md](DEVICE-THREAT-MODEL.md).

## Get the binary

**From your Omni server (recommended).** The Docker image builds the agent for
linux/amd64 and linux/arm64 — plus a tarball of the PAM module and systemd
unit sources — from the same commit as the server, and serves them on
**Account → Enroll a device** (`/account/enroll`) with SHA-256 checksums.
The page shows copy-paste install commands with your issuer filled in. Files
are public at `/downloads/<name>`; the server needs `downloads.dir`
(`OMNI_DOWNLOADS_DIR`, set to `/downloads` by the compose file).

**From source.** Pure Go, no CGO, cross-compiles from any host:

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

The default is the graphical page. Run the agent with no command and it
serves a small page on the loopback interface and opens it in your browser:

```bash
sudo omni-enrollment --issuer https://identity.example
```

Pick the device name and key storage, press **Enroll this device**, then
approve on this computer or by scanning the QR code with your phone. See
*Graphical enrollment* below for details.

On a machine without a display, over SSH, or in scripts, use the terminal
ceremony instead:

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

    █████████████████████████████
    ██ ▄▄▄▄▄ █▀ █▀▀██ ▄▄▄▄▄ ██     (QR code of the same link — scan it
    ██ █   █ █▀ ▄ ▀▄█ █   █ ██      with a phone; --no-qr / --qr-light
    …                                for narrow or light terminals)

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

## Graphical enrollment

```bash
sudo omni-enrollment --issuer https://identity.example      # same as: omni-enrollment gui …
```

serves a small page on the loopback interface and opens it in your browser
(like `tailscale web`): pick the server, device name, and key storage
(software file or TPM 2.0), press **Enroll this device**, then approve either
on this computer (button) or by scanning the QR code with your phone. Once
enrolled the same page shows the device's status, owner, key, and daemon
health with **Check trust now**, **Rotate key**, and **Unenroll**. It runs
the exact ceremony the CLI runs.

The page binds to 127.0.0.1 only; the printed URL carries a one-time token
that becomes a cookie, every action also needs that token in a request
header (so a web page in the same browser cannot drive it), and the Host
header must be loopback. Stop it with Ctrl-C when done, or pass
`--exit-when-idle 2m` to have it quit once the tab is closed.

Under `sudo` or `pkexec` the agent opens the page **as the desktop user**
(from `SUDO_USER` / `PKEXEC_UID`) with that session's `DISPLAY`,
`WAYLAND_DISPLAY`, `XAUTHORITY`, and D-Bus address, so the tab lands in
your own browser rather than in root's. If no browser opens, the URL is
printed anyway; paste it into any browser on the same machine.

### Desktop launcher

`endpoint/desktop` (also in the endpoint tarball on the *Enroll a device*
page) contains a `.desktop` entry, a polkit policy, and an icon:

```bash
sudo make -C endpoint/desktop install
```

adds **Omni Enrollment** to the application menu. Launching it asks for an
administrator password through the desktop's own polkit dialog
(`auth_admin_keep`, so the prompt is not repeated for a few minutes), starts
`omni-enrollment --exit-when-idle 2m` as root, opens the page in your
browser, and exits two minutes after the tab is closed. The policy pins the
executable to `/usr/local/bin/omni-enrollment`; edit both files if you
install the binary elsewhere.

## Commands

| Command | What it does |
|---|---|
| `gui [--issuer URL] [--listen 127.0.0.1:0] [--no-open] [--exit-when-idle D]` | Local web page to enroll and manage this device (see above). **Default:** running `omni-enrollment` with no command, or with flags only, is the same as `gui`. |
| `enroll --issuer URL [--name N] [--no-qr\|--qr-light] [--browser] [--key-backend file\|tpm]` | Generate the key and run the enrollment ceremony. Refuses if already enrolled. `--browser` authorizes through this machine's browser (RFC 8252 loopback redirect, authorization code + PKCE) instead of showing a code for another device. `--key-backend tpm` holds the device key in the TPM 2.0. |
| `status [--json]` | Show the enrollment record and the daemon's last renewal / error. Works offline. |
| `renew` | Obtain one device token now (RFC 7523 jwt-bearer grant). Exit 1 if Omni refuses (revoked) or is unreachable. |
| `rotate-key` | Generate a new key, register it (signed by both old and new key), then commit it locally. |
| `unenroll` | Revoke the device server-side (best effort) and delete the local key and record. |
| `daemon` | Renewal loop used by the systemd unit. |

Configuration precedence: flag > `OMNI_ENROLLMENT_*` environment > `/etc/omni-enrollment/config.yaml`.
The QR code (`qr: dark|light|off`) also applies to the Linux login prompt on
consoles and SSH. Graphical greeters (GDM, SDDM, LightDM) get the plain URL
and code unless `qr_greeters: true` (or `--qr-greeters`,
`OMNI_ENROLLMENT_QR_GREETERS=1`) is set, which sends them the same text QR.
That is best effort: greeters draw prompts in proportional fonts, and
whether the block glyphs line up depends on the greeter's font fallback, so
try it on one machine before enabling it fleet-wide.

## Files

| Path | Mode | Contents |
|---|---|---|
| `/var/lib/omni-enrollment/device.key` | `0600 root` | Ed25519 private key (PKCS#8 PEM), software backend. **Never leaves the machine.** |
| `/var/lib/omni-enrollment/device.tpm.json` | `0600 root` | TPM backend: SRK-wrapped private blob + public area. Useless without that TPM. |
| `/var/lib/omni-enrollment/device.json` | `0600 root` | device id, fingerprint, issuer, owner, last known status. No secrets. |
| `/run/omni-enrollment/status.json` | `0644` | daemon view: status, reachability, last renewal, token expiry, last error. No tokens. |
| `/run/omni-enrollment/pam.sock` | `0600 root` | PAM conversation socket (`pam_omni.so`). |
| `/run/omni-enrollment/nss.sock` | `0666` | read-only identity lookups (`libnss_omni`). |
| `/var/lib/omni-enrollment/users/<name>.json` | `0600 root` | per-user identity (uid, home) and offline cache; see the Linux login docs. |

The agent refuses to load a key file that is readable by other users.

## What the daemon does (and does not do)

Every half token lifetime (default 30 min; at least every minute) it performs
the jwt-bearer grant. Success → `status: active`. Omni unreachable → keeps the
last known status, backs off up to 15 min, `issuer_reachable: false`. Omni
answered but refused (device revoked, owner disabled) → `status: revoked`,
re-checked every 15 min; the operator must re-enroll.

It holds the device token in memory only. It does not run remote commands,
enforce policy, collect inventory, or talk to anything but the configured
issuer. The Linux login integration talks to the daemon over two Unix sockets: the
root-only PAM socket and the read-only NSS socket; that is the extent of its
local surface.

## Local token broker

With `broker_audiences` set in `config.yaml` (or `OMNI_ENROLLMENT_BROKER_AUDIENCES`),
the daemon brokers audience-bound access tokens for local applications run by
a signed-in Omni user, using RFC 8693 token exchange with the device as actor:

```bash
omni-enrollment token --audience omni-metrics          # prints a bearer token
omni-enrollment token --audience omni-metrics --json   # {"access_token":…,"expires_in":900}
```

The caller is identified by its uid on `/run/omni-enrollment/broker.sock`;
only users who have signed in online on this machine (and are not revoked)
get tokens, and only for the allowlisted audiences. The app never sees a
refresh token or the device key. Details: device architecture §10.

## Admin approval

If the server's *Require admin approval for new device enrollments* setting is
on, `enroll` ends with **PENDING administrator approval**. Start the daemon
anyway: it checks every minute (`status: pending` in `status.json`, never
"revoked") and becomes active as soon as an administrator approves the device
under **Devices**; a rejection shows up as revoked.

## Revocation from the user's side

**My Devices → Revoke** (or an admin under **Devices**). The next renewal fails
and the daemon records `revoked`. Any device-bound refresh tokens are revoked
immediately; outstanding device tokens expire within `device_token_ttl`
(default 1 h). A revoked key can never be re-enrolled; run `unenroll` then
`enroll` to start over with a new key.

## Hardware-backed keys (TPM 2.0)

Enroll with the key generated and held inside the machine's TPM so a copied
filesystem cannot impersonate the device:

```bash
sudo omni-enrollment enroll --issuer https://identity.example --key-backend tpm
# --tpm-device /dev/tpmrm0 (default) or tcp://host:port for a software TPM
```

The device gets an ECDSA P-256 key (`ES256`, already accepted by Omni) whose
private half never leaves the TPM; only the SRK-wrapped blob and public area
are stored, in `device.tpm.json`. `rotate-key` keeps using the TPM. The key
backend is recorded in `device.json` (`key_backend`, `tpm_device`), so the
daemon and rotation use it automatically. Secure Enclave/Keychain on Apple
platforms would slot in the same way behind the `enrollment.Signer` interface.
