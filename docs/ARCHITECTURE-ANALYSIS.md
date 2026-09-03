# Omni Identity — Existing Architecture Analysis

**Date:** 2026-09-02
**Purpose:** Phase 0 of the device-identity / passkey / Linux-login project. A
concise map of the subsystems the new work must plug into, so nothing is
recreated and nothing unrelated is refactored.

Baseline at analysis time: `main` @ `4bc0513`, ~18k lines of Go, `go test ./...`
green on SQLite; Postgres integration test gated by `OMNI_TEST_POSTGRES_URL`.

## 1. Shape of the codebase

```
cmd/omni-identity/         single server binary: serve | backup | integrity |
                           migrate-data | healthcheck | version
internal/config/           YAML + OMNI_* env overrides, validation, LDAP presets
internal/model/            dependency-free domain types (User, Session, Client,
                           RefreshToken, AuditEvent, Settings, …)
internal/store/            *sql.DB wrapper; SQLite (mattn, CGO) and Postgres (pgx)
                           behind one API; embedded migrations per dialect
internal/auth/             Argon2id passwords, TOTP, CSRF, session manager,
                           token hashing, password policy, random tokens
internal/authn/            connector contract (PasswordConnector, DirectoryManager)
internal/ldap/             the LDAP client connector (search-then-bind, JIT)
internal/crypto/           AES-256-GCM for at-rest secrets (TOTP)
internal/tokens/           signing keys (RS256 + EdDSA), JWKS, JWT issue/verify
internal/oidc/             discovery doc, PKCE, scopes
internal/email/            SMTP sender (password reset)
internal/logship/          best-effort log shipping to omnilog
internal/web/              http.ServeMux routes, middleware, handlers, templates
```

One process, one `Server` struct holding every dependency; no DI framework.

## 2. Authentication abstractions

- **Local password path** lives inline in `internal/web/auth_handlers.go`
  (`handleLoginSubmit`): lockout check → concurrency-bounded Argon2id verify →
  failed-login bookkeeping → rate-limit reset → MFA branch → session issue.
- **External connectors** implement `authn.PasswordConnector`
  (`Login(ctx, username, password) (Identity, ok, err)`). The server holds
  `[]authn.PasswordConnector`; LDAP is the only implementation. On success the
  identity is upserted into a local mirror row (`users.auth_source='ldap'`,
  `external_id`=DN, empty `password_hash`) by `store.UpsertExternalUser`.
- **The post-auth tail is shared**: whatever verified the first factor, the
  code continues to `startMFAChallenge` (if `user.MFAEnabled`) or
  `sessions.Issue(w, r, userID, amr)`. This is the seam a passkey login and a
  device-aware login must reuse: verify, then hand a `*model.User` to the same
  tail.
- **MFA** is TOTP (RFC 6238) or a hashed recovery code, gated by a server-side
  `login_challenges` row referenced from a 5-minute `omni_mfa` cookie
  (`mfa_handler.go`). The session records `amr="pwd mfa"` on success.
- **Boundary that matters for passkeys:** `User.IsLocal()` gates local-password
  flows (reset, change, forgot). Passkeys are an Omni-owned credential that
  must work for both local and LDAP users, i.e. they must not be gated by
  `IsLocal()`.

## 3. Sessions

- `auth.SessionManager` (`internal/auth/session.go`): opaque UUID in the
  `omni_session` cookie (HttpOnly, SameSite=Lax, Secure from live settings).
  Rows in `sessions` with `csrf_secret`, `user_agent`, `created_at`,
  `expires_at`, `last_seen_at` (idle timeout), `amr` (space-separated).
- `Issue` rotates the session id (deletes any inbound cookie's row first).
- `requireUser` / `requireAdmin` middlewares put `*model.User` and
  `*model.Session` on the request context (`userCtxKey`, `sessCtxKey`).
- CSRF: double-submit `omni_csrf` cookie (`auth.CSRFToken` /
  `ValidateCSRFToken`), used on every form POST via `csrfOK`.
- `Session.CreatedAt` doubles as OIDC `auth_time`.

## 4. OIDC / OAuth paths

Routes in `internal/web/server.go`:

| Endpoint | Handler | Notes |
|---|---|---|
| `GET /oauth2/authorize` | `authorize_handler.go` | validates client + exact redirect URI, PKCE S256 required for public clients, `prompt`, `max_age`; parks the request in `auth_requests` and redirects to `/login` or `/consent`, or issues a code |
| `POST /oauth2/token` | `token_handler.go` | `authorization_code`, `refresh_token` (rotation + reuse detection in `store.RotateRefreshToken`), `client_credentials` |
| `POST /oauth2/revoke` | `revoke_handler.go` | RFC 7009 for refresh tokens |
| `POST /oauth2/introspect` | `introspect_handler.go` | RFC 7662, confidential clients only, own tokens only |
| `GET/POST /userinfo` | `userinfo_handler.go` | bearer access JWT → claims by scope |
| `GET /.well-known/openid-configuration`, `GET /jwks.json` | `discovery_handlers.go` | doc built from the live issuer setting |

Key facts for the new work:

- `authenticateClient` resolves the client from Basic auth or POST body;
  public clients authenticate with `client_id` only. New grant types slot into
  the `switch` in `handleToken`.
- Access and ID tokens are minted by `tokens.Issuer` (`IssueAccessToken`,
  `IssueIDToken`) with fixed claim sets. The ID token currently carries
  `auth_time` but **no `amr`**; sessions do record AMR, so adding `amr` to ID
  tokens is additive.
- Refresh tokens are hashed at rest (`auth.HashToken` = SHA-256), keyed by
  `(client_id, user_id)`, and carry the original `auth_time`.
- Redirect URIs are matched exactly. Loopback `http://` is allowed by a live
  setting, but a loopback URI with a **different port** does not match (RFC
  8252 §7.3 asks servers to ignore the port for loopback); relevant if the
  enrollment client ever uses a browser-redirect flow.
- Discovery advertises `grant_types_supported` and
  `token_endpoint_auth_methods_supported`; new grants must be added there.

## 5. Signing / key infrastructure

- `tokens.KeyManager` generates and persists an RS256 (2048) and an EdDSA
  (Ed25519) key on first run (`signing_keys` table, PKCS#8 PEM private,
  public JWK JSON). All keys verify; the newest active key per alg signs.
  Default signer is RS256 for compatibility.
- `tokens.Issuer.Verify` checks kid → key, allowed algs `{RS256, EdDSA}`,
  issuer, expiry. This is reusable for verifying **Omni-issued** device tokens;
  verifying **device-signed** assertions (RFC 7523) needs a separate verifier
  keyed by the device's registered public key, not the JWKS.
- `golang-jwt/jwt/v5` is already a dependency; it supports EdDSA, ES256, RS256.
- `internal/crypto` gives AES-GCM with a persisted server secret
  (`app_secrets`) — the right place for any server-side secret that must be
  stored (there should be none for devices: only public keys are stored).

## 6. Persistence and migrations

- `store.DB` wraps `*sql.DB` in `dbConn`, which rewrites `?` placeholders to
  `$n` for Postgres. Queries are written once. Booleans are `INTEGER` in SQLite
  DDL and `BOOLEAN` in Postgres DDL but bind identically from Go.
- Migrations: `internal/store/migrations/{sqlite,postgres}/NNNN_name.sql`,
  embedded, applied in order inside a transaction each, statements split on
  `;` (no semicolons inside literals allowed). Next number: **0013**.
- Conventions: TEXT UUID primary keys, `TIMESTAMP`/`TIMESTAMPTZ`, `ON DELETE
  CASCADE` from users, `nullTime` for optional times, `requireRow` for
  update-must-match. `ErrNotFound` from getters.
- `migrate_data.go` copies every table SQLite → Postgres; **new tables must be
  added to its table list** or the migration tool silently skips them.
- Tests: `tempDB(t)` (SQLite in `t.TempDir()`), `openPostgresTest(t)` (gated).

## 7. Audit

- `Server.audit(r, event, auditEntry{actorUserID, username, clientID,
  success, detail})` writes an `audit_log` row **and** emits a structured slog
  line (`logAuditEvent`); warn level for failures. Event names are dotted
  constants in `internal/web/audit.go` (e.g. `login.success`,
  `admin.user.created`).
- Admin audit page filters on result, event type, username/IP. Adding new event
  constants is all that is needed for new event types to appear.
- Nothing sensitive is written to `detail` today; keep it that way (device ids
  are fine, keys/tokens/challenges are not).

## 8. Metrics

- Hand-rolled Prometheus text in `internal/web/middleware.go` (`metrics`
  struct): request counters, `logins_total{source,result}`, `mfa_total{result}`,
  `tokens_issued_total{type}`, plus `active_sessions` and `build_info` gauges
  rendered in `handleMetrics`. Bearer-token protected.
- Pattern to extend: add a map + `recordX` method + `writeLabeled` call. Labels
  are fixed enumerations only.

## 9. Admin / account UI patterns

- Go `html/template`, one parsed set per page composed with `base.html`
  (`templates.go`). All CSS is inline in `base.html`; CSP is
  `script-src 'self'` with **no inline scripts** — any WebAuthn JavaScript must
  be served as a static file from the same origin.
- Two shells: `shell-start/end` (admin sidebar, `.Active` selects the nav item)
  and `account-shell-start/end` (self-service, single column). Page structs carry
  `CSRFToken`, `Me`, `Active`, `Error`, `Saved`.
- Per-entity admin pages follow list → detail (`/admin/users`,
  `/admin/users/{id}`) with POST actions per row and `return=detail` to route
  back. Row menus use `<details class="menu">`.
- Self-service lives under `/account` (`requireUser`); admin under `/admin`
  (`requireAdmin`). Both are `Cache-Control: no-store`.

## 10. Live settings

`settingsService` (`settings.go`) caches a single `settings` row seeded from
config; `Current()` is read at use-time by the issuer, session manager, and
handlers. New tunables (e.g. a device-token TTL) follow the pattern: column via
migration → `model.Settings` → `SettingsView` → `viewFromModel`/`toModel` →
admin form. Infra-only knobs stay in config.

## 11. Test architecture

- Handler tests build a full `Server` on a temp SQLite DB (`testServer(t)`),
  drive it through `httptest` (`do(srv, req)`), and use helpers `createUser`,
  `createClient`, `startSession`, `postForm`, `enableMFA`, `cookieFrom`.
- OAuth flows are tested end to end (authorize → code → token → refresh →
  reuse detection). LDAP login is tested with a fake connector.
- No browser tests; templates are asserted by substring.

## 12. Constraints observed (do not break)

1. Every OIDC token issued via `authorization_code` / `refresh_token` /
   `client_credentials` keeps its current claim set; new claims only on new
   grants, plus the standard `amr` on ID tokens.
2. `User.IsLocal()` semantics and the LDAP upsert stay untouched.
3. One binary, embedded assets, no new external services.
4. Both dialects for every schema change; `migrate_data` table list updated.
5. Existing route names, cookie names, and audit event names unchanged.
