# Linux Login Architecture

**Date:** 2026-09-02
**Status:** Phase 5 design — implemented as the Phase 6 proof of concept
**Companion:** [DEVICE-IDENTITY-ARCHITECTURE.md](DEVICE-IDENTITY-ARCHITECTURE.md),
[DEVICE-THREAT-MODEL.md](DEVICE-THREAT-MODEL.md), [OMNI-ENROLLMENT.md](OMNI-ENROLLMENT.md)

The question this design answers: *can an enrolled Linux endpoint safely
establish an interactive Linux user identity using Omni Identity, keep
working offline, and never lock the owner out?*

---

## 1. The Linux authentication stack (what exists)

| Component | Role | Touched by this design? |
|---|---|---|
| **PAM** (`libpam`, `/etc/pam.d/*`) | Pluggable *authentication*: a service (`login`, `sshd`, `gdm-password`, `sudo`) runs a stack of modules; each can converse with the user through the service's conversation function. | **Yes — one small module is added to the stack.** Nothing is replaced. |
| **NSS** (`/etc/nsswitch.conf`, `passwd`/`group` sources) | *Identity lookup*: name ↔ uid/gid/home/shell. `files` reads `/etc/passwd`. | **Yes — one small source is added** (`libnss_omni`, after `files`). Nothing is replaced; `/etc/passwd` keeps every local account. |
| **SSSD** | Daemon providing NSS + PAM for LDAP/AD/IPA and, since 2.10, a generic OAuth2 *IdP* backend. | Evaluated, not used (§2). |
| **systemd-logind** | Session tracking, seats, `XDG_RUNTIME_DIR`, via `pam_systemd`. | **No.** Runs unchanged after PAM succeeds. |
| **Display managers** (GDM, SDDM, LightDM) | Drive PAM through their own greeter; render `PAM_TEXT_INFO` and prompts as text. | **No changes.** Text prompts are enough for the PoC; QR rendering is a greeter feature, not an identity one. |
| **`useradd`/`shadow`** | Local account database. | Untouched. Omni users are not written to `/etc/passwd`; the NSS source answers for them from the daemon's cache. |

Hard rule from the brief, honoured: PAM, NSS, logind, the display manager,
`/etc/passwd`, and the UID model are neither replaced nor reimplemented.

---

## 2. Options evaluated

| Option | How it would work | Verdict |
|---|---|---|
| **A. SSSD `ldap` provider** (architecture B in the brief) | SSSD ↔ the user's LDAP/AD directly. Cached credentials handled by SSSD. | Works today for LDAP users, but bypasses Omni entirely: no MFA, no passkeys, no device identity, no local users. Documented as the alternative for directory-only sites; not the target. |
| **B. SSSD `idp` provider** | SSSD performs the RFC 8628 device grant against the IdP and looks users/groups up through the IdP's REST API. | The right *shape*, but it only supports Entra ID and Keycloak because it needs their user/group APIs; Omni would have to impersonate Keycloak's admin API. Offline uses SSSD's cached-credential hash of the typed password — there is no typed Omni password in a device-grant login. Rejected for the PoC; a future `sssd-idp` profile for Omni remains possible. |
| **C. Ubuntu authd + a custom Omni broker** | authd owns PAM/NSS and offline (it sets a *local* password after the first online login); a broker speaks OIDC to the IdP over D-Bus. | Closest existing product to this design and the source of the local-password idea. Rejected for the PoC because it is Ubuntu-specific (snap-packaged, no Fedora), the broker D-Bus contract is still marked unstable, and it would make authd a hard dependency of a homelab. Worth revisiting if authd stabilises. |
| **D. himmelblau** | Rust PAM/NSS + daemon for Entra ID with Hello PIN offline. | Entra-only protocol (PRT). Confirms the pattern (thin PAM/NSS modules, privileged daemon, local PIN for offline); not reusable. |
| **E. `pam_oauth2_device`** and similar single-module projects | A C PAM module that runs the device grant itself and introspects the token. | Proves the device grant works at a PAM prompt (HPC sites use it). No offline mode, no provisioning, no device identity, secrets handled inside the module process. Reused as prior art for the conversation UX. |
| **F. `pam_exec` calling `omni-enrollment`** | No C code. | `pam_exec` cannot run a multi-step conversation (one password on stdin, stdout only to a TTY), so it fails at GDM/SSH. Rejected. |
| **G. Thin C PAM module ↔ root daemon over a Unix socket** (SSSD/authd/himmelblau pattern) | `pam_omni.so` relays the PAM conversation to `omni-enrollment daemon`, which does OAuth, verification, provisioning, and the offline cache. | **Chosen.** ~250 lines of C with no crypto or HTTP; everything security-relevant lives in one Go daemon that already holds the device key. Works with `login`, `sshd` (keyboard-interactive), GDM, `su`/`sudo`. |

---

## 3. Chosen design

```
  login / sshd / gdm                    omni-enrollment daemon (root)          Omni Identity
  ┌──────────────┐  PAM conversation   ┌───────────────────────────┐   HTTPS   ┌────────────┐
  │ pam_omni.so  │◀───────────────────▶│ /run/omni-enrollment/pam.sock│◀────────▶│ RFC 8628    │
  │ (relay only) │  line protocol      │  device key + device token │          │ + device    │
  └──────────────┘                     │  users/<name>.json cache   │          │   token     │
  ┌──────────────┐  name/uid lookups   │  home dir on first login   │          │ + user      │
  │ libnss_omni  │◀───────────────────▶│ /run/omni-enrollment/nss.sock│          │   lookup    │
  └──────────────┘  (read-only)        └───────────────────────────┘          └────────────┘
        │ success
  pam_unix (local accounts, break-glass) … pam_systemd → session
```

### 3.1 Online login (target architecture §18 of the brief)

1. PAM calls `pam_omni.so` with the requested username. The module connects
   to the daemon's root-only socket (`SO_PEERCRED` uid 0 enforced) and sends
   `AUTH <user> <service> <rhost>`.
2. The daemon obtains a **device token** (RFC 7523 jwt-bearer with the
   device key; §6 of the device architecture) and starts an RFC 8628 grant
   **authenticated by that token** (§7) with scope
   `openid profile email offline_access`. This is where the endpoint proves
   possession of the enrolled key during the ceremony (brief §19).
3. The user sees, through PAM messages: *Sign in at
   `https://identity.example/device?user_code=BCDF-GHJK`* — on any phone or
   laptop. On a console or SSH session the same link is also drawn as a
   half-block QR code (`qr: dark|light|off`); graphical greeters, which use
   proportional fonts, get the text only unless `qr_greeters: true` opts
   them in (best effort, depends on the greeter's font fallback). Omni's page shows *"Sign in on **omni-vm** (linux), enrolled by
   alice"*; the user authenticates with password / LDAP / TOTP / passkey and
   approves.
4. The daemon polls the token endpoint with the device token + DPoP and
   receives an ID token carrying `sub`, `preferred_username`, `amr`,
   `device_id`, `device_trust`, plus a device- and DPoP-bound refresh token.
   It verifies the ID token signature against the issuer's JWKS and requires
   `preferred_username` to equal the PAM username and `device_id` to equal
   its own device id (an approval by another account is refused).
5. **Provisioning** (§4): the identity (uid derived from `sub`, home, shell)
   is recorded in the daemon's cache — from now on `libnss_omni` answers for
   it — and the home directory is created from `/etc/skel`.
6. **Offline enrolment** (§5): on first login, the user chooses a *local
   password* for offline use. Its Argon2id hash, the identity mapping, and
   the refresh token are written to the root-only cache.
7. `R OK` → PAM_SUCCESS. The rest of the stack (`pam_systemd`, etc.) runs.

Nothing typed on the Linux machine ever reaches Omni: the daemon never
prompts for an Omni or LDAP password (brief §18).

### 3.2 Offline login (brief §20)

If a valid cache entry exists, the first prompt is
*"Local password (leave empty to sign in with Omni Identity):"*. A correct
local password within the **validity window** signs the user in with no
network at all. Empty input falls through to the online flow.

Validity policy (all configurable in `config.yaml`, defaults in brackets):

- `offline_validity` [168h]: offline login is allowed while
  `now < last_trust_refresh + offline_validity`. `last_trust_refresh` is
  advanced by every successful online login **and** by the daemon's
  background trust refresh (§3.3). A machine that has been offline for a
  week must go online once.
- Device status: the daemon's last known device status must not be
  `revoked` (from `status.json`); a revoked device refuses offline login.
- Cache entry not marked revoked (§3.3).

### 3.3 Trust refresh and revocation propagation

Every renewal cycle (half the device-token lifetime), the daemon also
redeems each cached user's device-bound refresh token (RFC 6749 refresh with
rotation, DPoP proof). Outcomes:

- success → `last_trust_refresh = now`, rotated token stored;
- Omni unreachable → nothing changes (offline window keeps counting down);
- Omni **refuses** (`invalid_grant`: device revoked, user disabled, token
  revoked) → the entry is marked `revoked` and offline login is refused
  from then on. This is how a revocation issued while the laptop was in a
  drawer takes effect the moment it reconnects.

Unavoidable property, stated plainly: while the machine is disconnected,
Omni cannot revoke anything on it. The offline window bounds the exposure.

### 3.4 Break-glass (brief §21)

`pam_omni.so` returns `PAM_IGNORE` for any account it does not manage
(present in `/etc/passwd` without an Omni cache entry) and is stacked as
`sufficient` **above** `pam_unix`, which stays `required`. Therefore:

- `root` and the local administrator `omni-recovery` authenticate through
  `pam_unix` exactly as before, with no network, no daemon, no Omni.
- If the daemon is down or the socket is missing, the module returns
  `PAM_IGNORE` (never `PAM_AUTH_ERR`), so local accounts are unaffected.
- The PoC setup creates `omni-recovery` in the `sudo`/`wheel` group with a
  strong password shown once. Nothing in this design ever removes or
  modifies it; it is documented as the recovery path in
  [LINUX-LOGIN-POC.md](LINUX-LOGIN-POC.md).

### 3.5 What the PAM module does and does not do

Does: `pam_get_user`, connect to the socket, relay `I`/`W` messages and
`P`/`E` prompts through the PAM conversation, return the verdict. Also
`account` (asks the daemon whether the cached identity is still valid).

Does not: touch the network, parse JSON, hold keys or tokens, read
`/etc/shadow`, or run as anything but the PAM caller's process. It is
deliberately boring.

---

## 4. Local identity mapping and provisioning (brief §17)

| Linux field | Value | Rationale |
|---|---|---|
| login name | Omni `preferred_username` | Must pass Linux name rules (lowercase, `[a-z_][a-z0-9_-]*`, ≤ 32); otherwise the login is refused with a clear message. Case-insensitive match against the PAM username. |
| uid = gid | `200000 + fnv1a32(sub) mod 100000`, probing upward on collision with `/etc/passwd` or another cached user | Deterministic from the stable Omni `sub`, so the same user gets the same uid on every enrolled machine (shared home directories stay consistent); range above typical local (1000+) and SSSD allocations. The allocation is recorded in the cache so a probe result is stable per machine. |
| home | `/home/<name>`, created by the daemon (0700, `/etc/skel`) on first login | Standard. |
| shell | `/bin/bash` (configurable `login_shell`) | Standard. |
| gecos | `Omni Identity <sub>` | Makes the origin visible in `getent passwd`. |
| password field | `*` | The identity is served by NSS, never written to `/etc/passwd`/`shadow`; only `pam_omni` can authenticate it. |
| groups | the private group only | Group/sudo policy is deliberately out of scope (not an MDM). Operators add groups locally (`gpasswd -a <name> <group>` works: supplementary membership lives in `/etc/group`). |

**How the system learns the identity.** `libnss_omni` (a glibc NSS source
listed after `files` for `passwd` and `group`) resolves names and ids through
the daemon's read-only socket `/run/omni-enrollment/nss.sock`. The daemon
answers from its user cache; for a name it has never seen it asks Omni once
(`GET /api/v1/users/lookup`, authenticated with the device token, budgeted at
30 lookups a minute, negative results remembered for a minute) and caches the
identity. This is what makes a *first* SSH login work: sshd resolves the user
with `getpwnam` before running PAM, and an identity that only exists in Omni
now resolves. Names present in `/etc/passwd` are never answered, so a local
account can never be shadowed by an Omni user of the same name. The enrolling
owner's identity is cached at enrollment time so it resolves even before the
first lookup. Offline, cached identities keep resolving; unknown names return
"not found" without waiting on the network.

Accounts are never deleted automatically; a revoked user simply cannot log
in. Deleting the account and its home is an operator decision.

---

## 5. Offline credential (brief §20, threat model §4.10)

The cache `/var/lib/omni-enrollment/users/<name>.json` (0600 root) holds:
`username`, `sub`, `uid`, `gid`, `home`, `secret_hash` (Argon2id of the
**local** password), `last_online_auth`, `last_trust_refresh`, `device_id`,
`amr` of the last online login, `refresh_token` (device- and DPoP-bound), and
`revoked` + reason.

Properties required by the brief:

- Does not store the Omni or LDAP password: the local password is chosen by
  the user and is only ever compared locally. ✔
- Independent of Omni reachability: verification is a local hash check. ✔
- Survives temporary outages: yes, up to `offline_validity`. ✔
- Explicit validity policy: `offline_validity`, device status, `revoked`. ✔
- Eventual trust refresh: daemon refresh (§3.3). ✔
- Revocation once connectivity returns: refresh failure marks `revoked`. ✔
- TPM-compatible later: the cache's secrets (refresh token) could be sealed
  to a TPM key via the same `Signer`/keystore abstraction; the hash needs no
  sealing. Not implemented. ✔ (design only)

Threat: a copied cache allows offline brute force of the local password
(same class as `/etc/shadow`); mitigated by Argon2id parameters and the
root-only mode. The refresh token in the cache is useless without the device
key (DPoP-bound) and dies with the device (device-bound).

---

## 6. Protocol between module and daemon

Newline-delimited UTF-8 lines over a Unix stream socket. No JSON in C.

| Direction | Line | Meaning |
|---|---|---|
| module → daemon | `AUTH <user> <service> <rhost\|->` | start an authentication |
| module → daemon | `ACCT <user> <service>` | account check |
| nss → daemon (`nss.sock`, world-connectable, read-only) | `PWNAM <name>` / `PWUID <uid>` / `GRNAM <name>` / `GRGID <gid>` | identity lookup; reply `PW <name> <uid> <gid> <home> <shell> <gecos>` / `GR <name> <gid>` / `NONE` |
| daemon → module | `I <text>` / `W <text>` | info / error message |
| daemon → module | `P <text>` / `E <text>` | prompt, echo off / on |
| module → daemon | `A <text>` | answer to the last prompt |
| daemon → module | `R OK <user>` / `R FAIL <reason>` / `R IGNORE` | verdict |

Peer credentials are checked on accept (uid 0 only). Each conversation runs
in its own goroutine with an overall deadline (the device grant's
`expires_in`, 10 minutes). sshd's `LoginGraceTime` must be ≥ that for
first-time online logins over SSH.

---

## 7. Scope statement

Implemented in the PoC: online login, NSS-served identities (first-time SSH
login for any Omni user), offline login with a local password, trust refresh,
revocation propagation, break-glass. Tested
with `sshd` and `login` in a disposable container; GDM is expected to work
because only standard PAM text prompts are used, but is not exercised.

Not implemented: group mapping, sudo policy, home-directory encryption,
screen-lock integration beyond PAM, QR codes in *graphical* greeters
(consoles and SSH have them), an `sssd-idp` profile, and an authd broker. None of these are needed
to answer the PoC question.
