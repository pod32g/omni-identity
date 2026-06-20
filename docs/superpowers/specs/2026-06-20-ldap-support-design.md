# LDAP Support — Design

**Date:** 2026-06-20
**Status:** Approved for implementation (direction confirmed with user)
**Scope:** Add **LDAP / Active Directory as an authentication backend** to Omni
Identity, following the industry-standard pattern: Omni acts as an LDAP **client**
that federates an external directory. Users sign in on the existing hosted login
page with their directory credentials; Omni binds to verify them, just-in-time
provisions a local mirror user, applies optional TOTP MFA, and issues OIDC tokens
as usual.

The backend is built as a **pluggable authentication connector** (the pattern
used by Dex/Keycloak user federation), so LDAP is the first of a family of
external sources rather than a one-off branch in the login handler.

### Decisions (captured from the user)

- **Direction:** inbound LDAP **auth backend / connector** only. We do *not*
  delegate to an external bridge (Dex/LLDAP) — that would mean Omni itself does
  not support LDAP, contradicting the goal. Being the LDAP client *is* the
  industry standard for an OIDC IdP.
- **MFA layering:** Omni's TOTP second factor still applies on top of an LDAP
  password bind, optional per user (an enrolled user is challenged after a
  successful bind). Falls out for free by routing LDAP users through the existing
  post-auth tail.
- **Admin mapping:** membership in a configurable LDAP group grants `is_admin`,
  re-evaluated on every login (fail-closed).
- **Standards posture (user picked "all of the above"):** standard library +
  **schema presets** (Active Directory / OpenLDAP), **pluggable connector**
  architecture, and **conformance hardening** (paged search, size/time limits,
  no referral chasing, injection-safe filters).
- **Outbound LDAP server: OUT OF SCOPE.** Per the user's rule "if the industry
  doesn't support an LDAP server, we neither": exposing an LDAP *server* is a
  minority feature (Authentik/Okta/JumpCloud offer it; Keycloak/Dex/Authelia/
  Zitadel core do not). It is not baseline for our class of tool, so it is
  deferred (see §6), not built now.

---

## 1. Guiding constraints

- **Don't weaken the existing hardened login path.** Local password auth, account
  lockout, per-IP+username rate limiting, CSRF, session-id rotation, and the MFA
  challenge stay exactly as they are. A connector is consulted *before* the
  session is issued, reusing the same downstream code.
- **Everything keys off a local `user_id`.** Sessions, OIDC auth codes, refresh
  tokens, and audit records all reference `users.id`, so external users need a
  local mirror row. We JIT-provision and refresh it on each login.
- **Don't reinvent the protocol.** Use `github.com/go-ldap/ldap/v3` (the de-facto
  standard Go LDAP library) and the standard **search-then-bind** flow. Use the
  library's `EscapeFilter`, paged search, and TLS helpers rather than hand-rolled
  equivalents.
- **Don't reinvent the architecture.** Model the connector interface on the
  established IdP pattern (Dex's `PasswordConnector`: `Login(...) (identity, ok,
  err)`), so future backends plug in identically.
- **Secrets live in config/env, never in web-editable settings.** The LDAP bind
  password and TLS material follow the SMTP precedent.
- **Config-gated and off by default.** With no LDAP config, behavior is identical
  to today; `make test` passes with zero LDAP servers reachable.
- **Both SQL dialects.** Schema changes ship parallel SQLite + Postgres
  migrations (matching `0001`–`0006`).

---

## 2. Connector abstraction (`internal/authn`)

A new leaf package (no store/web deps) defining the pluggable contract and the
identity shape, modeled on the industry connector pattern.

```go
package authn

import "context"

// Identity is a verified external identity returned by a connector.
type Identity struct {
    Connector   string // connector id, e.g. "ldap" (stored as users.auth_source)
    ExternalID  string // stable id within the source (LDAP entry DN)
    Username    string
    Email       string
    DisplayName string
    IsAdmin     bool
}

// PasswordConnector verifies a username/password against an external identity
// source. Modeled on Dex's connector interface: ok=false means invalid
// credentials (a normal negative, not an error); err is reserved for
// transport/config failures the operator must see.
type PasswordConnector interface {
    ID() string
    Login(ctx context.Context, username, password string) (id Identity, ok bool, err error)
}
```

The `web.Server` holds `connectors []authn.PasswordConnector` (empty by default).
LDAP is registered when configured. Adding SAML/social/SCIM later means writing a
new connector and registering it — no change to `handleLoginSubmit`.

---

## 3. LDAP connector (`internal/ldap`)

Implements `authn.PasswordConnector` with `ID() == "ldap"`. Library:
`github.com/go-ldap/ldap/v3` (pure-Go, no CGO).

### 3.1 Login algorithm (search-then-bind)

1. Reject empty username/password up front (empty password ⇒ some servers do an
   *unauthenticated bind* and return success).
2. Dial (`ldap://` + optional StartTLS, or `ldaps://`) honoring TLS config (CA
   file, `insecure_skip_verify` for labs), with a dial/op timeout.
3. Bind as the service account (`bind_dn`/`bind_password`), or anonymously if
   `bind_dn` is empty.
4. **Paged** subtree search of `base_dn` with `user_filter` (the `%s` is the
   `EscapeFilter`-escaped username), size-limited; expect exactly one entry. Read
   mapped attributes (username, email, display name) + the entry DN.
5. Fresh connection: **bind as the found DN with the submitted password**. Success
   ⇒ valid. `LDAPResultInvalidCredentials` ⇒ `ok=false`. Other errors ⇒ `err`.
6. Resolve admin: if `admin_group_dn`+`group_filter` set, base-scoped search of
   the admin group for the user DN ⇒ `IsAdmin`. Any error ⇒ not admin
   (fail-closed).
7. Return `authn.Identity{Connector:"ldap", ExternalID: dn, ...}`.

### 3.2 Schema presets

To avoid operators hand-writing filters (and to encode the standard schemas), a
`preset` selects defaults that explicit fields override:

| preset | user_filter | attr_username | attr_email | attr_display_name | group_filter |
|---|---|---|---|---|---|
| `activedirectory` | `(&(objectClass=user)(sAMAccountName=%s))` | `sAMAccountName` | `mail` | `displayName` | `(&(objectClass=group)(member=%s))` |
| `openldap` (default) | `(&(objectClass=inetOrgPerson)(uid=%s))` | `uid` | `mail` | `cn` | `(&(objectClass=groupOfNames)(member=%s))` |

Presets are applied in `config.Load` before explicit fields, so any field set in
YAML/env wins.

### 3.3 Conformance hardening

- **Paged results** via `conn.SearchWithPaging` (default page size 1000) so large
  directories don't truncate.
- **Size + time limits** on every search (`SizeLimit`, `TimeLimit` from the
  configured timeout).
- **No referral chasing** (`NeverDerefAliases`; referrals not followed) — avoids
  unexpected cross-server binds.
- **Injection-safe**: every user-supplied value goes through `ldap.EscapeFilter`.
- Connection is opened per-login (pooling is YAGNI for the expected login rate;
  documented as a future option).

### 3.4 Testing

Pure functions (filter render/escape, preset resolution, attribute mapping,
empty-password rejection) tested directly. A full bind/search test runs against a
real OpenLDAP gated behind `OMNI_TEST_LDAP_URL`, mirroring
`postgres_integration_test.go`.

---

## 4. Config, model, store

### 4.1 Config (`internal/config`)

`LDAPConfig` block (YAML + `OMNI_LDAP_*`), validated only when `enabled: true`:

```yaml
ldap:
  enabled: false
  preset: openldap                       # openldap | activedirectory
  url: ldaps://dc1.example.com:636
  start_tls: false
  bind_dn: "cn=svc-omni,ou=svc,dc=example,dc=com"   # empty ⇒ anonymous search
  bind_password: ""                      # SECRET — config/env only
  base_dn: "ou=people,dc=example,dc=com"
  user_filter: ""                        # overrides the preset
  attr_username: ""                      # overrides the preset
  attr_email: ""
  attr_display_name: ""
  admin_group_dn: "cn=omni-admins,ou=groups,dc=example,dc=com"
  group_filter: ""                       # overrides the preset
  ca_cert_file: ""
  insecure_skip_verify: false            # labs only
  timeout: 10s
```

Validation when enabled: `url` and `base_dn` required; the *effective* user_filter
(after preset) must contain `%s`.

### 4.2 Model + store

Add `User.AuthSource` (`"local"` default, else connector id e.g. `"ldap"`),
`User.ExternalID`, and `User.IsLocal()`. Migration `0007_ldap.sql` (both dialects)
adds the two columns + a partial unique index on `(auth_source, external_id)`.
Store gains `GetUserByExternalID` and `UpsertExternalUser(ctx, source, externalID,
username, email, displayName, isAdmin)` (flat params — `store` must not import
`authn`/`ldap`, avoiding a cycle). Upsert refuses to shadow an existing **local**
account with the same username.

---

## 5. Web integration

`web.Server` gains `connectors []authn.PasswordConnector`, built in `NewServer`
from `cfg.LDAP`. `handleLoginSubmit` credential check becomes source-aware:

1. Local user exists and `IsLocal()` → existing hardened path unchanged.
2. Otherwise, iterate `connectors`; first `ok==true` wins → `UpsertExternalUser`
   → fall into the **shared post-auth tail** (reset failures, MFA challenge if
   enrolled, session issue, audit, OIDC resume/redirect). Connector `err` is
   logged (operator-visible), never leaked to the browser.
3. None match → constant-time `DummyVerify` + generic invalid.

MFA layering is automatic (the upserted user flows through the existing
`if user.MFAEnabled` branch). Local-password flows (`/forgot`, `/set-password`,
`/account/password`, admin reset-link) are guarded to no-op/refuse for non-local
users. Admin UI shows an auth-source column (hiding password actions for directory
users) and a read-only "Directory (LDAP)" status panel (never the bind password).

Docs: `README.md`, `config.example.yaml`, `.env.example`.

---

## 6. Deferred / out of scope

- **Outbound LDAP server** (Omni answering bind/search) — minority feature, not
  baseline for an OIDC IdP; revisit only if a concrete consumer needs it.
- **Group → arbitrary role/scope** mapping beyond the single admin group.
- **Scheduled full-directory sync** (we provision lazily on login).
- **Password write-back** to the directory.
- **Connection pooling**, multiple/failover URLs (single URL initially).
- **Additional connectors** (SAML/social/SCIM) — the `authn.PasswordConnector`
  seam makes them additive later.
