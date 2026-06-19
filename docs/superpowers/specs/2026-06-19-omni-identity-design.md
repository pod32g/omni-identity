# Omni Identity — V1 Design Spec

Date: 2026-06-19
Status: Implemented — all 7 milestones built test-first; passed a multi-agent
review round (10 findings fixed). See git history for per-milestone commits.
Motto: *Boring identity for private infrastructure.*

## 1. Goal

A small, self-hosted OpenID Connect identity provider that lets Omni services
and standards-compatible third-party apps (e.g. Jellyfin) authenticate users
through a single Omni Identity login. Private by default, self-hosted first,
standards-compatible, one binary, SQLite first.

## 2. Foundational decisions (confirmed)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| JWT signing | **RSA + Ed25519 keypairs**, both in JWKS, **RS256 default signer** | Max client compatibility (Jellyfin/RS256) while publishing EdDSA for modern clients |
| SQLite driver | **CGO (`mattn/go-sqlite3`)** | Battle-tested. Tradeoff: build needs `CGO_ENABLED=1` + C toolchain; Makefile/Dockerfile provided |
| Password hashing | **Argon2id** (`golang.org/x/crypto/argon2`) | Modern, memory-hard, OWASP-preferred; cost params encoded per-hash |
| First admin | **First-run web wizard**, gated by `is_admin` flag | No chicken-and-egg; disables itself once an admin exists |
| Router | stdlib `net/http` (Go 1.22+ `ServeMux`) | "Boring", no framework dependency |
| Architecture | Layered monolith with a single `Store` interface | Idiomatic, testable; PostgreSQL can slot in later |

## 3. Module & layout

```
github.com/pod32g/omni-identity
├── cmd/omni-identity/main.go      # server + `admin` subcommands, flag parsing
├── internal/
│   ├── config/                    # YAML + env-override loading, validation
│   ├── store/                     # Store interface + sqlite impl + repos
│   │   └── migrations/*.sql       # embedded, versioned
│   ├── auth/                      # Argon2id hashing, sessions, CSRF
│   ├── tokens/                    # signing-key mgmt, JWT sign/verify, JWKS
│   ├── oidc/                      # discovery, authorize, token, userinfo, PKCE
│   ├── admin/                     # admin UI handlers + setup wizard
│   └── web/                       # router, middleware, embedded templates/static
├── web/templates/*.html  web/static/*   # embedded via embed.FS
├── config.example.yaml
├── Makefile  Dockerfile
└── go.mod
```

A single `store.Store` interface fronts the SQLite implementation so the future
PostgreSQL option requires no handler changes.

## 4. Data model

Deltas from the original spec are marked **bold**.

- **users**: `id` (UUIDv4), `username`, `email`, `password_hash`, **`is_admin`**,
  `disabled`, `created_at`, `updated_at`
- **clients**: `client_id`, **`client_secret_hash`** (secret never stored plaintext),
  `name`, `redirect_uris` (JSON array), `allowed_scopes` (JSON array), `type`
  (`public`|`confidential`), `disabled`, `created_at`, `updated_at`
- **sessions**: `id` (opaque random), `user_id`, `csrf_secret`, `user_agent`,
  `created_at`, `expires_at`
- **authorization_codes**: **`code_hash`** (SHA-256), `client_id`, `user_id`,
  `redirect_uri`, `scope`, `nonce`, `code_challenge`, `code_challenge_method`,
  `expires_at`, `used`, `created_at`
- **refresh_tokens**: `id`, **`token_hash`** (SHA-256), `client_id`, `user_id`,
  `scope`, **`rotated_from`**, `revoked`, `expires_at`, `created_at`
- **signing_keys**: `kid`, `alg` (`RS256`|`EdDSA`), `public_jwk`, `private_pem`,
  `active`, `created_at`

Hardening: client secrets, authorization codes, and refresh tokens are all
stored **hashed**, so a database leak never exposes live credentials.

## 5. OIDC behavior

- **Flows**: Authorization Code + **PKCE (S256)**; refresh tokens with
  **rotation + reuse detection** (replayed refresh token → revoke whole chain).
- **Tokens**: access + ID tokens are stateless JWTs carrying
  `sub, iss, aud, exp, iat, email, preferred_username` (+ `nonce`, `auth_time`
  on ID tokens). Refresh tokens are opaque random strings, stored hashed.
- **Endpoints**: `/.well-known/openid-configuration`, `/oauth2/authorize`,
  `/oauth2/token`, `/oauth2/revoke`, `/userinfo`, `/jwks.json`, `/login`,
  `/logout`.
- **Discovery advertises**: response type `code`; grants `authorization_code`,
  `refresh_token`; PKCE `S256`; signing `RS256`, `EdDSA`; scopes
  `openid profile email offline_access`; token-endpoint auth
  `client_secret_basic`, `client_secret_post`, `none` (public clients).
- **`/oauth2/revoke`** revokes refresh tokens immediately.
  *Honest limitation*: access tokens are stateless JWTs and cannot be
  individually revoked; their TTL is kept short (15m default) and revoking the
  refresh token stops renewal. This is standard IdP behavior and avoids a DB
  lookup on every resource request.

## 6. Sessions & security

- Opaque session id in an **HttpOnly, SameSite=Lax** cookie; **Secure** by
  default, toggleable for local `http://` dev. Server-side expiry via the
  `sessions` table.
- **CSRF**: synchronizer token bound to the session, required on every
  login/logout/admin POST.
- **Signing keys** generated on first boot, stored in DB, rotatable (multiple
  rows, one active per alg). Optional AES-GCM encryption of `private_pem` at
  rest using a key from config/env — provided as a clearly-marked toggle, off by
  default for V1.

## 7. Admin UI

Server-rendered `html/template`, embedded, gated by `is_admin`:

- **Login**, **Users** (list/create/disable/change password),
  **Applications/Clients** (list/create/disable/rotate secret),
  **Client detail** (edit redirect URIs & scopes), **Settings** (read-only
  issuer/URLs view for V1).
- **First-run wizard**: when no admin exists, the first visit serves a one-time
  create-admin page; it disables itself once an admin exists.

## 8. Config

`gopkg.in/yaml.v3` with environment-variable overrides for secrets. Shape
matches the original spec example (`server`, `database`, `security`), extended
with optional `cookies` (secure toggle) and `signing` (key-encryption) sections.

## 9. Process & testing

Test-driven per the superpowers workflow:

- Unit: Argon2id hashing, PKCE S256 verification, JWT sign/verify, JWKS
  marshaling, each store repo against a temp SQLite file.
- Integration: end-to-end `httptest` run of `authorize → token → userinfo →
  refresh → revoke`, including PKCE and refresh rotation/reuse detection.
- A final multi-agent review pass (security, OIDC-spec compliance, Go idioms,
  test coverage) before declaring V1 done.

## 10. Milestones

1. **Skeleton** — HTTP server, config loading, SQLite connection, migrations, health endpoint.
2. **Users** — user repo, Argon2id, login form, session cookie, logout, first-run wizard.
3. **OIDC discovery** — discovery endpoint, JWKS, signing-key generation.
4. **OAuth2 flow** — `/authorize`, code generation, `/token`, ID + access tokens, PKCE, refresh.
5. **Clients** — client repo, register Jellyfin/Omni clients, redirect-URI validation, secrets.
6. **Integration** — verify Jellyfin, Omni Metrics, Omni Logging against the running IdP.
7. **Polish** — admin UI, better errors, token revocation, basic logs & metrics.

## 11. V1 success criteria

- A user can log in to Omni Identity.
- Jellyfin, Omni Metrics, and Omni Logging can each authenticate via Omni Identity.
- Tokens are signed and verifiable through JWKS.
- A new OIDC client can be added in under 5 minutes.
- The whole system runs as one binary with SQLite.

## 12. Non-goals for V1

MFA, passkeys, LDAP, SAML, SCIM, social login, organizations, multi-tenancy,
complex RBAC, service accounts, API keys, audit-log UI, federation.
