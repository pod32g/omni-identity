# Device Identity Architecture

**Date:** 2026-09-02
**Status:** Phase 1 design — the reference for Phases 2 and 3
**Companion:** [DEVICE-THREAT-MODEL.md](DEVICE-THREAT-MODEL.md),
[ARCHITECTURE-ANALYSIS.md](ARCHITECTURE-ANALYSIS.md)

Omni Identity gains **devices** as a first-class principal next to users and
OAuth clients. A device is an endpoint that holds its own asymmetric key, was
explicitly enrolled by an authenticated user, and can later prove possession of
that key to obtain short-lived credentials. Everything below is built from
existing IETF standards; the only Omni-specific parts are the JSON shapes of
two small resource endpoints and the choice of claim names.

Guiding rule, restated: *boring identity for private infrastructure*. If a
standard covers a step, that step uses the standard.

---

## 1. Concepts and vocabulary

| Term | Meaning |
|---|---|
| **User identity** | An Omni user (`users.id`, the OIDC `sub`). Local or LDAP-backed. |
| **Device identity** | A device record (`devices.id`) plus the public key registered for it. The private key never leaves the endpoint. |
| **Device enrollment** | The one-time ceremony in which user *X* authorizes device *Y* and *Y*'s public key is bound to the record. |
| **Device authentication** | The device proving possession of its private key to Omni to receive a **device token**. |
| **Device authorization** | Omni deciding what an authenticated device may do (V1: obtain a device token; act as the enrolled context of a user login). |
| **Interactive OS login** | A user establishing a local Linux session with Omni's help (Phase 5/6). |
| **Offline OS login** | The same without Omni reachable (Phase 5/6). |

A user and a device are distinct principals. A device token names the device in
`sub`; a user token issued *on* a device names the user in `sub` and the device
in `device_id`.

---

## 2. Standards evaluated

| Standard | Use here | Verdict |
|---|---|---|
| **RFC 8252** OAuth for Native Apps | `omni-enrollment` is a public native client; no embedded secret; PKCE. | Adopted as the client posture. Browser-redirect (loopback) flow is optional (§5.4). |
| **RFC 7636** PKCE | Already implemented for `authorization_code`. | Reused wherever the code flow is used. |
| **RFC 8628** Device Authorization Grant | Enrollment and Linux login from an endpoint that has no usable browser at the login prompt. This is exactly what SSSD's IdP backend and Ubuntu's authd use for terminal login. | **Adopted.** Implemented in Omni (new). |
| **RFC 7523** JWT profile for OAuth: §2.1 JWT as authorization grant | The enrolled device presents a JWT signed with its private key to the token endpoint and receives a device token. The RFC's required "trust relationship" is the enrollment record (public key registered under user authorization). | **Adopted** for device authentication. |
| **RFC 9449** DPoP | Sender-constrains tokens to the device key: the enrollment token cannot be replayed with a different key (this is what defeats public-key substitution), and device/user tokens issued to the endpoint are useless if copied without the key. | **Adopted** (server: token endpoint + device API; client: proof per request). |
| **RFC 7638** JWK Thumbprint | Device fingerprint and DPoP `jkt` are the same value: `base64url(SHA-256(canonical JWK))`. | Adopted. |
| **RFC 8693** Token Exchange | The local broker exchanges the user's device-bound refresh token (subject) plus the device token (actor) for an app-scoped access token carrying `act`. | **Adopted** for the local token broker (§10). |
| **RFC 8705** mTLS client auth / certificate-bound tokens | Device certificates instead of raw keys. | **Rejected**: requires a CA and TLS-terminating proxies to pass client certs; the project forbids unnecessary PKI. |
| **RFC 7591** Dynamic Client Registration | Register each device as an OAuth client with `private_key_jwt`. Standards-pure but pollutes the Applications UI and makes `client_id` do double duty. | **Rejected** for V1; devices are their own table. The assertion format is still RFC 7523. |
| **RFC 8176** AMR values | Report *how* the user authenticated. | Adopted for `amr` on sessions and ID tokens. |
| **OIDC Core** `auth_time`, `amr`, `nonce` | Standard claims. | Adopted (`amr` is newly added to ID tokens; additive). |
| **OAuth 2.0 Security BCP (RFC 9700)** / OAuth 2.1 draft | Sender-constrained or rotated refresh tokens for public clients, exact redirect matching, PKCE everywhere. | Already largely met; DPoP closes the remaining gap for the native client. |
| **WebAuthn L2/L3 / FIDO2** | Passkeys for users (Phase 4). Independent of devices. | Adopted via `github.com/go-webauthn/webauthn`. |

Conclusion: **no custom protocol is required.** Every message the endpoint
sends to Omni is a standard OAuth request; the two resource endpoints
(`POST /api/v1/devices`, `POST /api/v1/devices/me/key`) are ordinary
DPoP-protected JSON resources.

---

## 3. Device model

Table `devices` (SQLite and Postgres migration `0013_devices.sql`):

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID; the `device_id` claim |
| `owner_user_id` | TEXT FK users | enrolling user; `ON DELETE CASCADE` |
| `name` | TEXT | user-chosen (defaults to hostname) |
| `hostname`, `platform`, `architecture` | TEXT | metadata reported at enrollment (`linux`, `arm64`, …) |
| `public_key` | TEXT | JWK JSON (public part only) |
| `public_key_algorithm` | TEXT | JWS alg: `EdDSA` (default), `ES256`, `RS256` |
| `fingerprint` | TEXT UNIQUE | RFC 7638 thumbprint of `public_key` |
| `status` | TEXT | `pending` \| `active` \| `revoked` |
| `trust_level` | TEXT | V1: `enrolled` (software key). Reserved: `hardware` (attested TPM/Secure Enclave key). |
| `owner_only` | BOOL | only the owner may sign in on this device (§7) |
| `created_at`, `enrolled_at`, `last_seen_at`, `revoked_at` | timestamps | `last_seen_at` updated on successful device authentication |
| `previous_fingerprint` | TEXT | set on key rotation, for audit/forensics |

Supporting tables:

- `device_assertion_jtis (jti_hash PK, device_id, expires_at)` — replay guard
  for RFC 7523 assertions and DPoP proofs; rows are pruned on insert.
- `device_codes` — RFC 8628 pending grants (see §5.2).
- `refresh_tokens.device_id` — new nullable column; refresh tokens issued via
  a device-authenticated grant are bound to the device and revoked with it.
- `refresh_tokens.dpop_jkt` — thumbprint the refresh token is bound to (public
  clients using DPoP), per RFC 9449 §5.

`status` semantics:

- `pending` is used when the admin setting *Require admin approval for new
  device enrollments* is on: the enrollment succeeds but the device cannot
  obtain credentials (the jwt-bearer grant answers `authorization_pending`,
  which the agent treats as "keep waiting", not as a revocation) until an
  administrator approves it under *Devices*. Rejecting is a revocation. With
  the setting off (default) enrollments go straight to `active` because the
  user's authenticated approval *is* the authorization.
- `revoked` is terminal. The row stays (with `revoked_at`) so audit history and
  the fingerprint blacklist survive. Admins may **delete** a revoked device
  row; deletion is a housekeeping action and is audited. A never-revoked
  device cannot be deleted without revoking first.

---

## 4. Device cryptographic identity

- Generated **on the endpoint** by `omni-enrollment`; default **Ed25519**
  (JWS `EdDSA`), chosen because it is already a first-class algorithm in
  Omni's JWT stack and has no parameter-choice footguns. **ES256 (P-256)** and
  **RS256** are accepted so a future TPM 2.0 or Secure Enclave key (which will
  typically be P-256 or RSA) drops in without a server change.
- **Key backend** is selectable (`--key-backend file|tpm`):
  - *file* (default): a software Ed25519 key at
    `/var/lib/omni-enrollment/device.key` (PKCS#8 PEM), directory
    `0700 root:root`, file `0600`, loaded only by the root-owned daemon/CLI.
  - *tpm*: an ECDSA P-256 key generated **inside a TPM 2.0** under the owner
    hierarchy's storage root key, with `fixedTPM` + `sensitiveDataOrigin` set.
    The private half never exists outside the TPM; the daemon stores only the
    SRK-wrapped private blob and the public area
    (`/var/lib/omni-enrollment/device.tpm.json`, `0600 root`), which only that
    TPM can load. Signing (RFC 7523 assertions, DPoP proofs) goes through
    `TPM2_Sign`; the key surfaces as a `crypto.Signer` with alg `ES256`, which
    Omni already accepts. Device: `/dev/tpmrm0` by default, or
    `tcp://host:port` for a software TPM (swtpm) in testing.
  The private key never reaches Omni in either case. Threat assumptions are in
  the threat model §4.
- The client code hides the key behind a `Signer` interface
  (`Public() JWK`, `Sign(alg, data)`), so a TPM-backed implementation can be
  added later without touching the protocol code.
- **Fingerprint** = RFC 7638 JWK thumbprint (SHA-256, base64url), identical to
  the DPoP `jkt`. Shown in the UI as the device's identifier for humans.
- Omni stores only: public JWK, algorithm, fingerprint, ownership, metadata,
  status, trust level, timestamps.

---

## 5. Enrollment protocol

### 5.1 Actors

- `omni-enrollment` — a **built-in public OIDC client** (`client_id =
  omni-enrollment`) created by migration `0013`. Type `public`, no secret,
  allowed scopes `openid device:enroll`, no redirect URIs by default (device
  grant needs none), `skip_consent = false` so the approval page is always
  shown. Admins can see it under Applications but it is marked *built-in*.
- Scope `device:enroll` — new Omni scope; "register this device under my
  account". Only `omni-enrollment` (or clients an admin explicitly allows) may
  request it.

### 5.2 Flow (RFC 8628 device grant + DPoP)

```
endpoint (omni-enrollment)                     Omni Identity
--------------------------                     -------------
1. generate device key K
2. POST /oauth2/device_authorization
     client_id=omni-enrollment
     scope=openid device:enroll
     device_name=omni-laptop platform=linux …  (metadata is display-only here)
                                     -------->  store device_code (hashed), user_code,
                                                client_id, scope, expires (10 min)
     <--------  {device_code, user_code, verification_uri,
                 verification_uri_complete, expires_in, interval}
3. print:  "Authenticate with Omni Identity:
            https://identity.example/device?user_code=ABCD-EFGH"
4. poll  POST /oauth2/token
     grant_type=urn:ietf:params:oauth:grant-type:device_code
     device_code=… client_id=omni-enrollment
     DPoP: <proof signed with K, htm=POST, htu=token URL, jti, iat>
                                     -------->  authorization_pending / slow_down
                                                until the user approves
                                          user: browser → /device → login (pwd / LDAP /
                                          TOTP / passkey) → approval page shows
                                          "Enroll device omni-laptop (linux)?" → Approve
     <--------  access_token (DPoP-bound: cnf.jkt = thumbprint(K)),
                id_token, scope=openid device:enroll, token_type=DPoP
5. POST /api/v1/devices
     Authorization: DPoP <access_token>
     DPoP: <proof signed with K, htm, htu, jti, iat, ath=hash(access_token)>
     {name, hostname, platform, architecture}
                                     -------->  verify proof; require proof.jwk thumbprint
                                                == token cnf.jkt; user = token sub;
                                                create device{owner=user, key=proof.jwk,
                                                status=active, trust=enrolled}
     <--------  201 {device_id, fingerprint, status, trust_level, owner}
6. persist device_id + fingerprint in /var/lib/omni-enrollment/device.json
```

Why this establishes "authenticated user X explicitly authorized device Y":

- The user authenticated through Omni's normal hosted login (all existing
  factors, including passkeys) and saw a page naming the device before
  approving. No credential of the user ever touched the endpoint.
- The **public key bound to the device record is the DPoP key from step 5**,
  and that key must equal the `cnf.jkt` the token was bound to in step 4. A
  token stolen after step 4 cannot register a different key; a proof replayed
  from another host fails on `jti` reuse, `htu`, and the 5-minute `iat` window.
- The device grant's `user_code` is single-use, 10-minute, and shown to the
  user only via Omni's own page; the `device_code` is 32 random bytes stored
  hashed and never displayed.

### 5.3 Resistance summary (details in the threat model)

| Threat | Control |
|---|---|
| CSRF on approval | Approval is a CSRF-protected POST behind a logged-in session; `user_code` alone does nothing. |
| Replay of token poll / API call | DPoP `jti` single-use, `iat` ±5 min, `htm`/`htu` bound. |
| Enrollment code theft | `device_code` never leaves the client except over TLS to the token endpoint, is hashed at rest, expires in 10 min, and is consumed once. `user_code` is worthless without the user's session. |
| Public-key substitution | Key registered = DPoP proof key = `cnf.jkt` of the token bound at issuance. |
| Unauthorized registration | Scope `device:enroll` limited to the built-in client; approval page requires a session; audit event. |
| Login-CSRF at approval | The approval page shows the *approving* user's identity; a device enrolled under an attacker's account would appear in the attacker's list, not the victim's. |

### 5.4 Alternative: authorization code + PKCE with loopback redirect

`omni-enrollment enroll --browser` implements RFC 8252 §7.3: it opens the
system browser at `/oauth2/authorize` with a `code_challenge`, listens on
`http://127.0.0.1:<ephemeral port>/callback`, and exchanges the code with the
`code_verifier` and a DPoP proof, so the access token is device-bound exactly
as in step 4. The built-in client registers `http://127.0.0.1/callback` and
`http://[::1]/callback` (migration 0015) and the server ignores the port for
registered literal-loopback `http://` redirects — and only for those. Steps
5–6 are identical. The device grant stays primary because it works from a VM
console, an SSH session, and a display-manager prompt alike.

### 5.5 Front ends: terminal, local page, launcher

The ceremony above is exposed twice by the same code path
(`enrollment.BeginEnrollment` → `Wait`):

| Front end | Invocation | Notes |
|---|---|---|
| Local page (**default**) | `omni-enrollment [--issuer URL]`, or `omni-enrollment gui` | Serves an HTML page on `127.0.0.1:<ephemeral>`, opens it in the user's browser, shows the verification link, user code, and QR code, then the device card with renew / rotate / unenroll. |
| Terminal | `omni-enrollment enroll` | Prints the same link, code, and a half-block QR; for SSH, consoles, scripts, and the PoC. `--browser` selects §5.4. |
| Desktop launcher | `endpoint/desktop` | `.desktop` entry → `pkexec omni-enrollment --exit-when-idle 2m`; polkit asks for an administrator password, the page opens as the desktop user, and the process exits after the tab is closed. |

The local page is a front end, not a protocol: it never handles Omni
credentials (approval always happens on Omni's own `/device` page, in a
normal signed-in browser session) and it adds no server-side endpoint. Its
own surface is bounded as follows: it binds to the loopback interface only;
the printed URL carries a one-time 192-bit token that becomes a
`SameSite=Strict`, `HttpOnly` cookie; every state-changing request must also
carry that token in an `X-Omni-GUI` header, so a page on another origin
cannot drive it even with the cookie present; the `Host` header must be a
loopback name; responses carry a restrictive CSP and `no-store`; and the
process can stop itself when idle. Under `sudo`/`pkexec` the browser is
launched as the invoking desktop user (from `SUDO_USER` / `PKEXEC_UID`) with
that user's session environment, never as root. Threats are in
[DEVICE-THREAT-MODEL.md §4.17](DEVICE-THREAT-MODEL.md).

---

## 6. Device authentication (RFC 7523 JWT-bearer grant)

After enrollment the endpoint holds only `device_id`, the key, and the issuer
URL. To obtain a **device token**:

```
POST /oauth2/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
client_id=omni-enrollment
assertion=<JWT>
DPoP: <proof signed with K>            (optional but recommended; binds the token)
```

Assertion (signed with the device key, header `alg` = registered algorithm,
`kid` = fingerprint):

```json
{ "iss": "<device_id>", "sub": "<device_id>", "aud": "<issuer>",
  "iat": 1725000000, "exp": 1725000300, "jti": "<random 128-bit>" }
```

Server checks, in order: assertion parses; `iss == sub`; device exists and
`status == active`; signature verifies with the **registered** public key
(never the JWKS); `aud` equals the issuer; `exp - iat ≤ 5 min` and not
expired; `jti` unused (insert into `device_assertion_jtis`, unique). On
success `last_seen_at` is updated and a device token is issued:

```json
{ "iss": "<issuer>", "sub": "<device_id>", "aud": "omni-enrollment",
  "token_use": "device", "device_id": "<device_id>",
  "device_trust": "enrolled", "owner_sub": "<user_id>",
  "cnf": {"jkt": "<fingerprint>"},           // when DPoP was presented
  "iat": …, "exp": … }
```

Lifetime: `device_token_ttl`, default **1 hour**, live-editable in Admin →
Settings. No refresh token is issued for this grant; the device simply
re-asserts. This keeps revocation latency ≤ 1 h with zero state.

Failure responses use RFC 6749 codes (`invalid_grant`), never distinguishing
"unknown device" from "revoked device" to the caller (the audit log does).

What a device token is for in V1:

- `GET /api/v1/devices/me` — status/trust snapshot for `omni-enrollment status`.
- `POST /api/v1/devices/me/key` — key rotation (§8).
- `POST /api/v1/devices/me/unenroll` — self-revocation.
- Authenticating an RFC 8628 request so the resulting *user* tokens carry
  device claims (§7).

---

## 7. User-on-device: device-aware login

The Linux login agent (Phase 6) authenticates a *user* from an *enrolled
device*. Omni's profile of RFC 8628 for this case:

1. The endpoint obtains a device token (§6).
2. `POST /oauth2/device_authorization` with `Authorization: DPoP <device
   token>` (and a DPoP proof). Omni binds the pending grant to `device_id`.
   Without the header the request is an ordinary anonymous device grant
   (still supported, no device claims).
3. The verification page tells the user *which device* is asking
   ("Sign in to **omni-laptop** (linux), enrolled by *alice*") and, after the
   normal login, records the session's `amr` on the grant.
4. The token poll must present the **same** device token; the issued tokens
   then carry:

   - ID token: `sub`, `auth_time`, `amr` (e.g. `["pwd","otp"]` or
     `["webauthn","user","mfa"]`), `device_id`, `device_trust`.
   - Access token: `device_id`, `device_trust`, `cnf.jkt` if DPoP.
   - Refresh token (if `offline_access`): stored with `device_id`; revoked
     when the device is revoked.

`device_trust` values: `enrolled` (the device authenticated with an active,
software-key enrollment); reserved `hardware`. **Absence of the claim means
"no device context"**, which is what every existing client keeps seeing.

Which tokens may carry device claims:

| Grant | `device_id` / `device_trust` present |
|---|---|
| `authorization_code`, `refresh_token` (of a non-device token), `client_credentials` | **never** (unchanged) |
| `urn:…:jwt-bearer` (device assertion) | always (device token) |
| `urn:…:device_code` **with** device-token authentication | yes (user-on-device) |
| `urn:…:device_code` without | no |
| `refresh_token` of a user-on-device refresh token | yes, copied from the stored binding, only while the device is active |

Trustworthiness: the claims are trustworthy to the extent the JWT signature
is — they are asserted by Omni after a proof-of-possession, never copied from
client input. A client that needs them must verify the JWT and check
`device_trust == "enrolled"`; a client that does not care ignores them.

Owner vs. login user: by default any active Omni user may sign in on any
active device (a shared homelab box). An owner can flip a device to
**owner only** under *My Devices*; Omni then refuses device-bound login
approvals by anyone else, both on the approval page and at the token
endpoint. That is the whole policy surface — deliberately not a policy engine.

---

## 8. Key rotation

`POST /api/v1/devices/me/key`, authenticated with a DPoP-bound device token
whose `cnf.jkt` is the **current** key. Body:

```json
{ "jwk": { …new public key… },
  "proof": "<JWT signed with the NEW key: aud=<endpoint URL>, iat, exp≤5m, jti,
            'old_jkt'=<current fingerprint>>" }
```

Server: verifies the device token (current key possession), verifies `proof`
with the new JWK (new-key possession), checks `old_jkt` matches, the new
fingerprint is not already registered (including revoked rows), then
atomically replaces `public_key`/`public_key_algorithm`/`fingerprint`, sets
`previous_fingerprint`, audits `device.key.rotated`. Both keys sign, so neither
a stolen token nor a stolen new key alone can rotate. A revoked device cannot
rotate (device token issuance already fails). If the current key is lost, the
only path is re-enrollment (fresh user authorization → new device id).

---

## 9. Revocation semantics

- Users revoke their own devices at `/account/devices`; admins at
  `/admin/devices` and `/admin/users/{id}`. Both require CSRF-protected POSTs.
- Effects, immediately: `status=revoked`, `revoked_at` set; all refresh tokens
  with that `device_id` revoked; `device.revoked` audited.
- Effects, bounded by TTL: outstanding device tokens (≤ 1 h) and user
  access/ID tokens issued on the device (≤ `token_ttl`, default 15 min) stay
  cryptographically valid until they expire. Omni's resource endpoints
  (`/api/v1/devices/*`, `/userinfo` for device-bound tokens) re-check status on
  every call, so *Omni itself* stops honouring them at once; third-party
  resource servers verifying JWTs offline cannot. This is documented rather
  than papered over; the mitigation is short lifetimes.
- A revoked device's fingerprint can never be re-registered.
- Disabling or deleting the owner user cascades: devices are deleted with the
  user (FK cascade) and every device grant fails because the owner lookup
  fails.

---

## 10. Local token broker (RFC 8693)

`omni-enrollment daemon` can broker tokens for local Omni applications so
they never store user credentials of their own:

```
local app (uid 200123)           omni-enrollment daemon (root)              Omni Identity
  │ TOKEN omni-metrics  ────────▶ │ SO_PEERCRED → uid → cached user alice     │
  │                               │ audience ∈ broker_audiences allowlist?    │
  │                               │ POST /oauth2/token grant=token-exchange ─▶│ subject = alice's device-bound
  │                               │   subject_token = refresh token (DPoP)    │   refresh token (not consumed)
  │                               │   actor_token   = device token (DPoP)     │ actor = this device
  │ ◀──── TOKEN 900 <jwt> ─────── │ ◀──────── access token aud=omni-metrics ──│ sub=alice, act={sub:device},
  │                               │                                            │ device_id, amr; plain bearer
```

Server side, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
accepts only the built-in client, requires a DPoP proof, and checks: the
actor token is a DPoP-bound device token for the presented key and an active
device; the subject token is a live refresh token bound to that same device
and key; the audience is a registered, enabled client; the scope is within
both the user's grant and the audience's allowed scopes. The issued token is
a normal access token for that audience with `act: {sub: <device_id>}`,
`device_id`, `device_trust`, `amr`, `auth_time` (the user's original
sign-in time, carried over from the refresh token — the exchange itself is
not an authentication), and `groups` (`["admins"]` for an administrator,
absent otherwise) — the RFC 8693 delegation shape, so a resource server can
distinguish "alice via her enrolled laptop" from a plain user token, apply
its own freshness policy, and tell whether she administers Omni. It is a bearer with the normal short TTL because the local app
holds no device key.

Endpoint side, the broker socket (`/run/omni-enrollment/broker.sock`) is
world-connectable but every request is authorized by the caller's uid: only
uids that map to a cached user who has signed in online on this device and is
not revoked get anything, root and system uids are refused, and the audience
must be on the operator's `broker_audiences` allowlist (empty = broker off).
`omni-enrollment token --audience <client id>` is the CLI for scripts.

A random local process therefore does not gain access merely because the
daemon runs: it needs to *be* the signed-in user, and only for audiences the
operator chose. Per-app user approval on first use is a possible refinement
and is not implemented.

## 11. Endpoint and UI inventory (Phase 2)

New HTTP surface:

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /oauth2/device_authorization` | client id (public) or device token | RFC 8628 §3.1 |
| `POST /oauth2/token` grant `device_code` | client id (+DPoP) | RFC 8628 §3.4 |
| `POST /oauth2/token` grant `jwt-bearer` | device assertion (+DPoP) | RFC 7523 §2.1 |
| `POST /oauth2/token` grant `token-exchange` | device token + device-bound refresh token (+DPoP) | RFC 8693 (local broker) |
| `GET /device`, `POST /device` | session | user-code entry + approval page |
| `POST /api/v1/devices` | DPoP-bound access token, scope `device:enroll` | enroll |
| `GET /api/v1/devices/me` | device token | status |
| `POST /api/v1/devices/me/key` | device token (+ new-key proof) | rotate |
| `POST /api/v1/devices/me/unenroll` | device token | self-revoke |
| `GET /account/devices`, `POST /account/devices/{id}/revoke` | session | My Devices |
| `GET /admin/devices`, `GET /admin/devices/{id}`, `POST /admin/devices/{id}/revoke`, `POST /admin/devices/{id}/delete` | admin session | management |

Discovery additions: `device_authorization_endpoint`, grant types
`urn:ietf:params:oauth:grant-type:device_code` and
`urn:ietf:params:oauth:grant-type:jwt-bearer`,
`dpop_signing_alg_values_supported: ["EdDSA","ES256","RS256"]`, scope
`device:enroll`, claims `amr`, `device_id`, `device_trust`.

Audit events: `device.enrollment.started`, `device.enrollment.completed`,
`device.enrollment.failed`, `device.authentication.success`,
`device.authentication.failed`, `device.key.rotated`, `device.revoked`,
`device.deleted`, `device.approved`, `device.policy.updated`,
`device.login.approved` (user-on-device grant approved).

Notifications (when SMTP is configured, best-effort): the owner is emailed on
every enrollment (with a revoke link) and on approval; administrators are
emailed when an enrollment awaits approval.

Metrics: `omni_identity_device_enrollments_total{result}`,
`omni_identity_device_auth_total{result}`, `omni_identity_devices_active`
(gauge), `omni_identity_device_grants_total{result}` (RFC 8628 outcomes).
No device ids, hostnames, users, or fingerprints as labels.

---

## 12. Known limitations (V1)

- With the software key backend, a copied filesystem is a cloned device
  (threat model §4). With `--key-backend tpm` the wrapped blob is inert on any
  other machine, so a copied filesystem cannot sign — this is the mitigation
  for §4.9.
- Revocation of already-issued JWTs is bounded by their TTL.
- No attestation; `trust_level` is a label, not a measurement.
- One built-in enrollment client; third-party enrollment clients are not a
  goal.
