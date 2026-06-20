# LDAP Support — Design

**Date:** 2026-06-20
**Status:** Approved for implementation (direction confirmed with user)
**Scope:** Add LDAP support to Omni Identity in two directions:

- **Phase 1 — LDAP authentication backend (inbound / Omni as LDAP client).** Users
  sign in on the existing hosted login page with their LDAP / Active Directory
  credentials; Omni binds to the directory to verify them, just-in-time
  provisions a local mirror user, and issues OIDC tokens as usual.
- **Phase 2 — LDAP server (outbound / Omni as LDAP server).** Omni listens on an
  LDAP port and answers bind + search so legacy apps that only speak LDAP can
  authenticate against Omni's local user directory.

Decisions captured from the user:

- **Both** directions are in scope (Phase 1 first, then Phase 2).
- **MFA layering:** Omni's TOTP second factor still applies on top of an LDAP
  password bind, optional per user (an enrolled user is challenged after a
  successful bind).
- **Admin mapping:** membership in a configurable LDAP group grants `is_admin`,
  re-evaluated on every login.

---

## 1. Guiding constraints

- **Don't weaken the existing hardened login path.** Local password auth, account
  lockout, per-IP+username rate limiting, CSRF, session-id rotation, and the MFA
  challenge stay exactly as they are. LDAP is an additional credential source
  layered *before* the session is issued, reusing the same downstream code.
- **Everything keys off a local `user_id`.** Sessions, OIDC auth codes, refresh
  tokens, and audit records all reference `users.id`. LDAP users therefore need a
  local mirror row. We just-in-time (JIT) provision and refresh it on each login.
- **Secrets live in config/env, never in web-editable settings.** The LDAP bind
  password and TLS material follow the SMTP precedent: configured via
  `config.yaml` / `OMNI_*` env vars only. The admin UI shows LDAP status
  read-only.
- **Config-gated and off by default.** With no LDAP config, behavior is identical
  to today. `make test` must pass with zero LDAP servers reachable.
- **Both SQL dialects.** Every schema change ships parallel SQLite + Postgres
  migrations, matching the existing `0001`–`0006` pattern.

---

## 2. Phase 1 — LDAP authentication backend (inbound)

### 2.1 New package `internal/ldap`

A small, dependency-isolated client. Library: `github.com/go-ldap/ldap/v3`
(pure-Go, the de-facto standard; no CGO, consistent with the single-binary goal).

```go
package ldap

// Identity is the directory's answer for a verified user.
type Identity struct {
    ExternalID  string // stable id: the user entry DN (or objectGUID if mapped)
    Username    string
    Email       string
    DisplayName string
    IsAdmin     bool   // resolved from admin-group membership
}

// Authenticator verifies credentials against the directory.
type Authenticator interface {
    Authenticate(ctx context.Context, username, password string) (*Identity, error)
}

// Client is the configured LDAP authenticator.
type Client struct { /* cfg + dialer */ }

func New(cfg Config) (*Client, error)
func (c *Client) Authenticate(ctx context.Context, username, password string) (*Identity, error)
```

Errors: `ErrInvalidCredentials` (bad user/password — caller maps to the generic
"invalid username or password"), and wrapped transport errors for
unreachable/misconfigured servers (caller logs + shows a generic error, never
leaks detail to the browser).

**Auth algorithm (search-then-bind — the standard, safe pattern):**

1. Dial the server (`ldap://` + optional StartTLS, or `ldaps://`), honoring TLS
   config (CA file, `insecure_skip_verify` for labs only).
2. Bind as the service account (`bind_dn` / `bind_password`). If `bind_dn` is
   empty, support anonymous search.
3. Search `base_dn` (scoped `sub`) with `user_filter` where `%s`/`{username}` is
   the **escaped** submitted username; expect exactly one entry. Read the mapped
   attributes (username, email, display name) and the entry DN.
4. Open a fresh connection and **bind as the found DN with the submitted
   password**. Success ⇒ credentials valid. (Rebind as the service account or
   drop the connection afterward; never reuse the user-bound conn for search.)
5. Resolve admin: if `admin_group_dn` is set, run `group_filter` (default
   `(&(objectClass=groupOfNames)(member=%s))` with the user DN, or for AD
   `(member:1.2.840.113556.1.4.1941:=%s)` for nested groups) and set `IsAdmin` to
   whether the admin group is among the results — or, simpler default, a single
   membership check against `admin_group_dn`.
6. Return `Identity`.

**Security details:**
- Always escape the username into filters via `ldap.EscapeFilter` to prevent LDAP
  injection.
- Reject empty passwords up front (an empty password can yield an *unauthenticated
  bind* that some servers accept as success).
- Time-bound every network step with the request context / a dial timeout.

**Testing:** filter templating, attribute mapping, and admin resolution are pure
functions tested directly. A full bind/search test runs against a real directory
(OpenLDAP) gated behind an env var, mirroring `postgres_integration_test.go`
(`OMNI_TEST_LDAP_URL`). Optionally add a docker-compose service for local runs.

### 2.2 Config (`internal/config`)

New `LDAPConfig` block (YAML + `OMNI_LDAP_*` env overrides), validated only when
`enabled: true`.

```yaml
ldap:
  enabled: false
  url: ldaps://dc1.example.com:636      # ldap:// or ldaps://
  start_tls: false                      # upgrade a ldap:// connection to TLS
  bind_dn: "cn=svc-omni,ou=svc,dc=example,dc=com"   # empty ⇒ anonymous search
  bind_password: ""                     # SECRET — config/env only
  base_dn: "ou=people,dc=example,dc=com"
  user_filter: "(&(objectClass=person)(uid=%s))"    # %s = escaped username
  attr_username: uid
  attr_email: mail
  attr_display_name: cn
  admin_group_dn: "cn=omni-admins,ou=groups,dc=example,dc=com"   # empty ⇒ no LDAP admins
  group_filter: "(&(objectClass=groupOfNames)(member=%s))"      # %s = user DN
  ca_cert_file: ""                      # PEM for a private CA
  insecure_skip_verify: false           # labs only
  timeout: 10s
```

`func (c LDAPConfig) Enabled() bool`. Validation when enabled: `url`, `base_dn`,
and `user_filter` are required; `user_filter` must contain a `%s`. Env keys:
`OMNI_LDAP_ENABLED`, `_URL`, `_START_TLS`, `_BIND_DN`, `_BIND_PASSWORD`,
`_BASE_DN`, `_USER_FILTER`, `_ATTR_USERNAME`, `_ATTR_EMAIL`,
`_ATTR_DISPLAY_NAME`, `_ADMIN_GROUP_DN`, `_GROUP_FILTER`, `_CA_CERT_FILE`,
`_INSECURE_SKIP_VERIFY`, `_TIMEOUT`.

### 2.3 Data model + store (`internal/model`, `internal/store`)

Add to `model.User`:

```go
AuthSource string // "local" (default) or "ldap"
ExternalID string // LDAP entry DN (or objectGUID); "" for local users
```

Add `func (u *User) IsLocal() bool { return u.AuthSource == "" || u.AuthSource == "local" }`.

**Migration `0007_ldap.sql`** (SQLite + Postgres):

```sql
ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_users_external ON users(auth_source, external_id)
    WHERE external_id <> '';   -- Postgres partial index; SQLite supports this too
```

Store changes:
- Extend `userColumns`, `scanUser`, and `CreateUser` for the two new columns.
- Add `GetUserByExternalID(ctx, source, externalID)`.
- Add `UpsertLDAPUser(ctx, *Identity) (*model.User, error)` (or an
  `UpsertExternalUser`) that: looks up by `(auth_source='ldap', external_id)`;
  inserts a new row (new UUID, `auth_source='ldap'`, empty `password_hash`) on
  miss; otherwise updates email/display/is_admin; returns the row. Username
  collisions with an existing **local** user are rejected (the local account
  wins; LDAP login for that username is refused with a logged error) to prevent
  privilege confusion.

### 2.4 Login-flow integration (`internal/web`)

Add an optional `ldap ldap.Authenticator` field to `Server` (nil when disabled),
wired in `NewServer` from `cfg.LDAP`.

Modify `handleLoginSubmit` minimally. After `ParseForm` + CSRF + rate-limit, the
credential check becomes source-aware:

1. Look up the local user by username.
2. **Local user exists and `IsLocal()`** → existing path unchanged (lockout check,
   `VerifyPassword`, failure bookkeeping).
3. **No local user (or the row is an `ldap` user) and LDAP is enabled** → call
   `s.ldap.Authenticate`. On `ErrInvalidCredentials` → existing `invalid()`
   (rate-limit fail + generic error + audit `login.failed` detail `ldap`). On
   transport error → log, audit, generic error. On success → `UpsertLDAPUser`,
   then **fall into the shared post-auth tail**.
4. **Neither** → `invalid()` (with `DummyVerify` to preserve constant timing).

The **shared post-auth tail** (reset failure state, MFA challenge if
`user.MFAEnabled`, else `sessions.Issue`, audit `login.success`, resume parked
OIDC request / redirect) is reused unchanged. Because MFA is checked on the
returned user, **TOTP layering on LDAP is automatic** — an LDAP user who enrolled
TOTP gets challenged.

Account lockout: LDAP credential failures are governed by Omni's per-IP+username
rate limiter (unchanged) and by the directory's own lockout policy; Omni's
DB-row lockout counter applies to local users only. Documented as such.

**Guard local-only flows for LDAP users** (they have no local password):
- `/forgot`, `/set-password`, `/account/password`: when the target user is an
  LDAP user, do not issue/accept a reset and show "managed by your directory" (or
  silently no-op for `/forgot` to preserve enumeration resistance). The admin
  "send reset link" action is hidden/blocked for LDAP users.

**Audit:** reuse `login.success` / `login.failed` with `detail: "ldap"` (no new
event constants strictly required; may add `auth.source` detail).

### 2.5 Admin UI

- Users list: show an "auth source" column (Local / LDAP) and a directory badge;
  hide password-reset actions for LDAP users.
- Settings page: a **read-only** "Directory (LDAP)" section showing
  enabled/disabled, server URL, base DN, and admin-group — values come from
  config (consistent with how SMTP status is surfaced). Optionally a "Test
  connection" button (bind as the service account) — *nice-to-have, may defer*.

### 2.6 Docs

Update `README.md` (features + a "Directory / LDAP" section), `config.example.yaml`
(the `ldap:` block, commented), and `.env.example` (the `OMNI_LDAP_*` vars).

---

## 3. Phase 2 — LDAP server (outbound)

Omni runs an LDAP server so apps that only speak LDAP can authenticate against
Omni's **local** users.

### 3.1 Package `internal/ldapserver`

Library candidate: `github.com/jimlambrt/gldap` (maintained Go LDAP-server
library) — confirmed available at implementation time, else fall back to
`github.com/nmcclain/ldap`. The server:

- **Bind:** maps a bind DN (e.g. `uid=<username>,<user_base_dn>` or a configured
  pattern) to a local Omni user and verifies the password against the stored
  Argon2id hash via `auth.VerifyPassword`. **Only local users with a password
  hash can bind** — LDAP-sourced users (Phase 1) and passwordless accounts
  cannot; this is an inherent limitation and is documented.
- **Search:** answers queries under the configured base DN, returning user entries
  (and optionally group entries derived from `is_admin`) with a small, fixed
  attribute set (`uid`, `cn`, `mail`, `objectClass`). A configured service/bind
  account gates search; anonymous search is off by default.
- Honors account `disabled` and `locked` state (refuse bind).
- Optional LDAPS via configured cert/key.

### 3.2 Config + wiring

```yaml
ldap_server:
  enabled: false
  listen: ":3893"
  base_dn: "dc=omni,dc=local"
  user_rdn_attr: uid          # bind DN shape: <user_rdn_attr>=<username>,ou=people,<base_dn>
  tls_cert_file: ""
  tls_key_file: ""
  bind_dn: ""                 # service account allowed to search (empty ⇒ search disabled)
  bind_password: ""           # SECRET — config/env only
```

`cmd/omni-identity/runServe` starts the LDAP listener alongside the HTTP server
(own goroutine, shared `errCh`, graceful shutdown on the same signal context),
only when `ldap_server.enabled`.

### 3.3 Testing

Drive the server in-process with a `go-ldap` client in unit tests (bind success /
failure / disabled user / search results). No external dependency required.

---

## 4. Rollout / sequencing

1. **Phase 1** end to end (config → model/store/migration → `internal/ldap` →
   login integration → guards → admin UI → docs → tests). This alone delivers the
   common meaning of "support LDAP."
2. **Phase 2** (server package → config → main wiring → tests → docs).

Each phase is independently shippable and leaves `make test` green with no LDAP
servers present.

---

## 5. Out of scope (YAGNI for now)

- LDAP **group → arbitrary role/scope** mapping beyond the single admin group.
- Background/scheduled directory **sync** of all users (we provision lazily on
  login only).
- Password **write-back** to LDAP and self-service password change against the
  directory.
- Connection **pooling** for the LDAP client (open per-login; revisit if load
  warrants).
- Multiple/failover LDAP URLs (single URL initially; `go-ldap` allows adding
  later).
