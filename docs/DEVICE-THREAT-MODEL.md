# Device Identity — Threat Model

**Date:** 2026-09-02
**Scope:** device enrollment, device authentication, device-aware user login,
the `omni-enrollment` endpoint agent, and the Linux login PoC. Passkeys are
covered only where they interact with devices (they are a user credential and
follow the WebAuthn threat model).
**Companion:** [DEVICE-IDENTITY-ARCHITECTURE.md](DEVICE-IDENTITY-ARCHITECTURE.md)

This document is honest about what the design does *not* solve. A homelab
threat model with software keys cannot claim to defeat physical compromise.

---

## 1. Assets

| Asset | Where | Sensitivity |
|---|---|---|
| Device private key | endpoint, `/var/lib/omni-enrollment/device.key` (0600 root) | Highest on the endpoint. Possession = the device. |
| Device record + public key | Omni DB | Integrity matters; confidentiality does not. |
| Device token (≤ 1 h JWT) | endpoint memory / daemon state | Bearer unless DPoP-bound; short-lived. |
| User access / ID tokens issued on a device (≤ 15 min) | endpoint memory | Same. |
| Device-bound user refresh token | endpoint state, hashed in Omni DB | Long-lived; DPoP-bound and device-bound; revoked with the device. |
| RFC 8628 `device_code` / `user_code` | endpoint memory / user's eyes; hashed in DB | 10-minute one-time values. |
| DPoP / assertion `jti` list | Omni DB | Replay guard. |
| Offline login cache (Phase 6) | endpoint, root-only | Contains an Argon2id hash of a *local* secret and identity mapping; never an Omni/LDAP password. |
| Omni server signing keys, app secret | Omni DB | Unchanged; out of scope here. |

Never stored anywhere by this design: user passwords, LDAP passwords, TOTP
secrets, passkey private keys, plaintext codes/tokens in the DB.

---

## 2. Assumptions

Attacker capabilities assumed (from the project brief):

- The endpoint can be stolen and its filesystem copied.
- Malware may run as an unprivileged local user on the endpoint.
- Network traffic can be observed (TLS is assumed for Omni; an attacker who
  can break TLS is out of scope).
- Requests may be replayed.
- Enrollment URLs and user codes may leak (shoulder-surfing, screenshots, chat).
- Attackers may know device ids, usernames, hostnames, and fingerprints.
- Omni Identity, the private network (Tailscale), or the LDAP backend may be
  temporarily unreachable.
- Users revoke devices, sometimes after the fact.

Trusted:

- Omni Identity's server and database (an attacker with write access to the
  DB can insert public keys and is already root of the identity system).
- Root on the endpoint at enrollment time and while the daemon runs.
- The user's browser session when approving an enrollment or a login.
- Go's `crypto/*`, `golang-jwt`, and `go-webauthn` implementations.

---

## 3. Trust boundaries

```
 ┌──────────────── endpoint ────────────────┐      TLS      ┌──────── Omni ────────┐
 │ unprivileged user ─┐                      │  ───────────▶ │ /oauth2/* /api/v1/*  │
 │   (malware here)   │ Unix socket (root)   │               │ DB: devices, jtis,   │
 │ pam_omni.so ───────┼──▶ omni-enrollment   │               │     device_codes     │
 │ (runs as root)     │    daemon (root)     │               └──────────────────────┘
 │                    │    holds device.key  │
 └────────────────────┴──────────────────────┘
                 ▲ user's browser (any machine) approves at /device
```

Boundary 1: unprivileged user ↔ root daemon (Unix socket, peer credentials).
Boundary 2: endpoint ↔ Omni (TLS; DPoP and assertions add proof of key).
Boundary 3: user's approving browser ↔ Omni (session cookie, CSRF).

---

## 4. Threats and controls

### 4.1 Device impersonation ("I know a device id")

*Attack:* an attacker learns `device_id` (it is in tokens, logs, UI) and tries
to obtain a device token or make a device-authenticated login request.

*Control:* every device-authenticated operation requires a JWS signed with the
registered private key (RFC 7523 assertion or DPoP proof). The id is public by
design. **Test scenario 15** (copying only the id fails) covers this.

### 4.2 Enrollment replay

*Attack:* replay a captured token-poll or `POST /api/v1/devices` request.

*Control:* DPoP proofs carry `jti` (stored, single-use until expiry), `iat`
(accepted within ±5 minutes), `htm`, `htu`, and `ath` (hash of the access
token). The `device_code` is consumed on first successful poll. Scenario 17.

### 4.3 Enrollment code / URL theft

*Attack:* the `user_code` or `verification_uri_complete` leaks (screenshot,
chat). The attacker opens it.

*Control:* the page only lets a **logged-in** user approve, so the attacker
enrolls the device under *their own* account, not the victim's — they gain
nothing about the victim, and the victim's CLI (whose `device_code` the
attacker does not have) receives a token for the attacker's account, which the
CLI displays ("enrolled as *mallory*"), making the mismatch visible. The
reverse — attacker obtaining the `device_code` — requires reading the client's
memory or TLS stream. Codes expire in 10 minutes and are single-use.

Residual: a user who is socially engineered into approving a code they did not
generate enrolls the attacker's machine under their account. The approval page
shows the device name/platform and warns to approve only a device you are
looking at; when SMTP is configured the owner is emailed about every new
device with a revoke link, and administrators can require approval of every
enrollment. Without SMTP the user must notice it in *My Devices*.

### 4.4 Public-key substitution

*Attack:* an attacker who obtains the enrollment access token registers *their*
key instead of the device's.

*Control:* the access token is DPoP-bound (`cnf.jkt`) to the key that signed
the token-poll proof; the enrollment endpoint registers exactly the DPoP proof
key and requires it to match `cnf.jkt`. A token without the key is inert.

### 4.5 Token theft on the endpoint

*Attack:* malware reads a device token or user token from the daemon's memory
or from a client process.

*Control:* tokens are short-lived (device ≤ 1 h, user access ≤ 15 min) and,
when DPoP-bound, unusable at Omni without the key. Refresh tokens are
DPoP-bound and device-bound. The daemon does not write tokens to disk in V1
except the device-bound refresh token used for the Linux login cache, which is
root-only and DPoP-bound.

Residual: a JWT verified offline by a third-party resource server is a bearer
to that server until expiry. Bounded by `token_ttl`.

### 4.6 Refresh-token theft

*Attack:* copy a device-bound refresh token.

*Control:* rotation with reuse detection (existing), DPoP binding (new: the
refresh grant must present a proof from the bound key), device binding (revoked
with the device). Copy without the key fails; copy *with* the key is §4.9.

### 4.7 Local privilege escalation via the daemon

*Attack:* an unprivileged local process talks to the daemon's Unix socket to
obtain tokens or trigger a login.

*Control:* the PAM socket is `0600 root:root`; only root (PAM stacks of
`login`, `sshd`, `gdm`, `sudo`) may connect. The daemon checks `SO_PEERCRED`
and rejects non-root peers. The broker socket is world-connectable but
authorizes every request by the caller's uid: tokens are issued only to the
uid of a user who signed in online on this device and is not revoked, only
for allowlisted audiences, and only as short-lived bearer tokens for that
audience; root and system uids are refused. A local process running *as the
user* can obtain what the user could obtain anyway; one running as another
user cannot.

### 4.8 Malicious local applications

Same as 4.7. An application running as the signed-in user can ask the broker
for tokens for allowlisted audiences — that is the feature — but never for
other audiences, never a refresh token, and never the device key. Operators
choose the allowlist; an empty list disables the broker.

The NSS socket (`nss.sock`) is world-connectable by necessity (any process
resolves names) but read-only: it answers name/uid queries from the cache and
performs at most 30 online username lookups a minute, with negative caching.
What it can leak is whether a username exists in Omni — information the
device, as a trusted principal, is entitled to, and that `getent` on any
directory-joined machine exposes the same way. It never returns secrets.

### 4.9 Device cloning (filesystem copy or stolen disk)

*Attack:* copy `/var/lib/omni-enrollment` to another machine.

*What happens:* the clone **is** the device to Omni; it can obtain device
tokens and, with the cached refresh token, user tokens on the device, until the
owner revokes it. Software keys cannot prevent this. Full-disk encryption is
the endpoint-side mitigation; the design-side mitigation is the `Signer`
abstraction that lets a TPM/Secure Enclave key (non-exportable) replace the
file key later, at which point a copied filesystem is inert.

*Detection:* concurrent use from two hosts shows as `last_seen_at`/audit IPs
alternating; DPoP `jti` collisions from two clones can trip the replay guard.
No automatic clone detection is claimed.

*Mitigation available now:* enrolling with `--key-backend tpm` binds the key
to the machine's TPM 2.0, so a copied filesystem cannot sign for the device;
the private key never leaves the TPM. The offline-login local secret and
cache are not yet TPM-sealed (future work).

*Not solved:* physical theft of an unencrypted, unlocked machine with a
software key, or an attacker who can drive the live TPM as root. Stated
plainly.

### 4.10 Offline credential theft (Phase 6)

*Attack:* copy the offline login cache.

*What is in it:* the user's Omni `sub`, username, uid mapping, timestamps, an
Argon2id hash of a **local unlock secret** the user chose, and a validity
window. Not the Omni or LDAP password.

*Impact:* offline brute force of the local secret (same class of risk as
`/etc/shadow`, which is why the file is root-only). A cracked local secret
grants a *local* session on the *stolen* machine only; it grants nothing at
Omni. Revocation still takes effect the moment the machine reconnects.

### 4.11 Revoked-device behaviour

- Online: new device tokens refused (`invalid_grant`); device-bound refresh
  tokens refused; user-on-device grant refused; API calls with a still-valid
  device token refused (status re-checked). ≤ 1 h until every outstanding
  device token has expired.
- Offline endpoint: **cannot be told**. It continues to honour its offline
  cache until the cache's validity window ends or connectivity returns and the
  daemon learns the revocation (it then invalidates the cache and refuses
  further offline logins). This is an unavoidable property of offline
  authentication and is documented, not hidden. The validity window is the
  operator's knob (default 7 days in the PoC).

### 4.12 Browser-based CSRF and login CSRF

- Approval and revocation are POSTs with the existing double-submit CSRF
  token; `user_code` in a GET only pre-fills the form.
- Login CSRF (attacker logs the victim's browser into the attacker's account
  and then the victim approves a device): the approval page names the
  signed-in user prominently; the device would land in the attacker's list,
  giving the attacker nothing from the victim.

### 4.13 Replay of the RFC 7523 assertion

`jti` unique per device until `exp`; `exp - iat ≤ 5 min`; `aud` fixed to the
issuer; signature keyed by the registered key. Scenario 17.

### 4.14 Denial of service against replay tables

`device_assertion_jtis` grows with legitimate traffic (one row per assertion
or proof, pruned on insert once expired). An attacker with a valid device key
could spam assertions; without one, requests fail before any insert. Existing
per-IP rate limiting is applied to the token endpoint's new grants.

### 4.15 Omni / network / LDAP unavailable

- Device token renewal fails → the daemon keeps the last known status and
  retries with backoff; nothing on the endpoint breaks because device tokens
  are only needed to talk to Omni.
- Interactive login falls back to the offline mechanism within its validity
  window (Phase 6). Break-glass local admin is independent of everything.
- LDAP down: LDAP-backed users cannot complete *online* login (existing
  behaviour); their offline cache still works on enrolled endpoints.

### 4.16 Server-side compromise

Out of scope: an attacker who controls the Omni DB can register keys. Device
identity does not raise or lower this risk.

---

### 4.17 Local enrollment page and desktop launcher

*Surface:* `omni-enrollment` (no command) runs an HTTP server as root on the
loopback interface and opens it in a browser; `endpoint/desktop` starts that
process through `pkexec` from the application menu.

*Attack:* a web page open in the same browser, or another local user, drives
the page to enroll, rotate, or unenroll the device; a local process on a
different host name reaches it; a launched instance is left running as root;
the browser (and its profile) runs as root.

*Controls:*

- Listens on `127.0.0.1` / `::1` only; the Host header must be a loopback
  name (403 otherwise), which also defeats DNS-rebinding.
- The launch URL carries a one-time 192-bit token. It is exchanged for a
  `SameSite=Strict`, `HttpOnly` cookie on first visit and removed from the
  URL; without the cookie nothing is served. Every `POST` must additionally
  carry the token in an `X-Omni-GUI` header, which only script on the page's
  own origin can add, so a cross-origin form or fetch fails with 403 even
  with the cookie present. Comparisons are constant-time.
- Restrictive CSP (`default-src 'self'`, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `Cache-Control: no-store` on every response; no
  external resources.
- Approval itself never happens on the local page: the user signs in on
  Omni's `/device` page in a normal session (with its own CSRF and identity
  wording, §4.3, §4.12), so the local page holds no Omni credential and no
  token; it holds the same state the CLI holds (device key, record).
- `--exit-when-idle` (used by the launcher) stops the server when no browser
  has talked to it for the period and no approval is pending. Ctrl-C or
  session end stops it otherwise.
- Under `sudo`/`pkexec` the browser is opened as the invoking desktop user
  (`SUDO_USER` / `PKEXEC_UID`, uid ≠ 0) with that session's display
  variables; root never runs a browser. The polkit policy pins the executable
  path (`org.freedesktop.policykit.exec.path`) and requires `auth_admin`
  (`auth_admin_keep` for the active session), so a non-administrator cannot
  launch it and the launcher cannot be pointed at another binary.
- Other local users cannot reach the page without the token: the URL is
  printed to the launching terminal (or handed straight to the browser) and
  is not written to any world-readable file.

*Residual:* a compromised browser profile of the desktop user that already
has the cookie could drive the page for as long as it runs; the same profile
could equally approve devices on Omni. Bounded by the idle exit and by every
action being visible under *My Devices*.

## 5. Residual risks (accepted, V1)

1. Software device keys are clonable by root or by disk theft without FDE.
2. Issued JWTs remain valid at third-party verifiers until expiry after
   revocation (≤ `token_ttl` / `device_token_ttl`).
3. Offline login cannot learn of revocation while offline.
4. Social-engineered enrollment approval is possible; mitigated by UI wording
   and the device list, not prevented.
5. No attestation: `device_trust=enrolled` means "a key was registered under
   user authorization", not "the OS is healthy".
6. Enrollment notifications depend on SMTP being configured.

## 6. Security tests required (mapped to the brief's scenarios)

| # | Scenario | Test location |
|---|---|---|
| 9 | Private key never reaches Omni | client unit test: enrollment request body and headers contain no private material; server schema has no private-key column |
| 13, 14 | Device proves possession and obtains a device token | `internal/web/device_grant_test.go` |
| 15 | Device id alone cannot authenticate | same: assertion signed with a different key → `invalid_grant` |
| 16 | Invalid proof fails | malformed / wrong `aud` / expired / wrong alg |
| 17 | Replayed proof fails | same `jti` twice → second fails |
| 18–20 | Revocation stops new credentials; issued ones expire | revoke → jwt-bearer fails, refresh fails, API with old token fails |
| — | Public-key substitution | enrollment with a DPoP key ≠ `cnf.jkt` → 401 |
| — | CSRF on approve/revoke | missing token → 403 |
| — | Local page: foreign Host, missing cookie, missing CSRF header → 403; idle exit; browser opened as the desktop user | `internal/enrollment/gui_test.go`, `internal/enrollment/openuser_test.go`, PoC `endpoint/poc/scripts/gui-enroll.sh` |
| — | Existing OIDC flows unchanged | existing suite + assertion that `authorization_code` tokens have no device claims |
