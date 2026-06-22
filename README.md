# Omni Identity

> Boring identity for private infrastructure.

A small, self-hosted OpenID Connect (OIDC) identity provider. It lets Omni
services and standards-compatible third-party apps (e.g. Jellyfin) authenticate
users through a single Omni Identity login. Private by default, self-hosted
first, one binary, SQLite.

## Features (V1)

- Local users with Argon2id password hashing
- **LDAP / Active Directory** authentication backend (optional): sign in with
  directory credentials, just-in-time provisioning, group→admin mapping, with
  Omni's TOTP MFA still layered on top — and optional write management to
  create / edit / delete / set passwords for directory users from the admin panel
- OIDC: Authorization Code flow + **PKCE (S256)**, refresh tokens (with rotation
  & reuse detection), ID tokens, access tokens
- **Hosted, branded login page** — unauthenticated authorization requests are
  parked server-side and the user is sent to a polished `/login` ("Sign in to
  continue to *<app>*") that shows the requesting application's name, logo, and
  domain; an existing session skips login automatically
- **Per-client consent** — trusted first-party apps skip consent; third-party
  apps get a consent screen listing the requested scopes and the user identity
- **RP-initiated logout** (`/logout`) with `id_token_hint`,
  `post_logout_redirect_uri` (exact allowlist), and `state`; revokes the
  browser's refresh tokens for the client
- **Configurable branding** (product name, uploaded logo, accent color, footer,
  background) applied to the login, consent, logout, and error pages
- **Rich client metadata**: display name, logo URL, homepage, allowed redirect &
  post-logout URIs, public/confidential type
- Login hardening: CSRF, per-IP+user **rate limiting**, session-id rotation,
  generic errors, exact redirect matching (no wildcards / open redirects)
- Signed JWTs (RSA **RS256** default, plus Ed25519 **EdDSA**) published via JWKS
- Discovery endpoint (`/.well-known/openid-configuration`)
- Minimal admin UI: users, applications (clients), branding settings
- First-run web wizard to create the initial admin
- Token revocation (RFC 7009) for refresh tokens
- Structured request logging and a basic Prometheus-style `/metrics` endpoint
- Single binary + SQLite

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for how applications add a
**"Continue with Omni Identity"** button using Authorization Code + PKCE.

## Build

The SQLite driver uses CGO, so a C compiler is required.

```sh
make build          # CGO_ENABLED=1 go build -o omni-identity ./cmd/omni-identity
make test           # go test ./...
```

Cross-compiling needs a cross C toolchain (e.g. `zig cc` or a musl
cross-compiler). The output is still a single self-contained binary.

## Configure

Copy `config.example.yaml` to `config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8080
  public_url: https://identity.omni.local   # required; used as the issuer base
  allow_insecure_http: false                 # true only for non-local http:// dev/private testing
  read_header_timeout: 10s
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  max_header_bytes: 1048576

database:
  driver: sqlite                              # sqlite (default) or postgres
  path: ./omni-identity.db                    # used when driver = sqlite
  url: ""                                      # postgres DSN when driver = postgres

security:
  issuer: https://identity.omni.local        # defaults to public_url
  setup_token: ""                            # required for first-run setup on non-loopback public URLs
  token_ttl: 15m
  refresh_token_ttl: 720h
  rate_limit_window: 15m
  login_ip_max_attempts: 20
  password_verify_concurrency: 4
  max_login_username_bytes: 320
  max_login_password_bytes: 1024
  allow_loopback_http_redirects: true
  max_failed_logins: 5
  lockout_duration: 15m
  password_min_length: 12
  require_upper: false
  require_lower: false
  require_number: true
  require_symbol: false
  session_lifetime: 12h
  session_idle_timeout: 0

cookies:
  secure: true                                # required for https:// public_url

metrics:
  bearer_token: ""                            # empty disables /metrics

uploads:
  max_logo_bytes: 524288                      # PNG/JPEG/WebP logos only
```

Any value can be overridden by environment variables, e.g. `OMNI_SERVER_PORT`,
`OMNI_DATABASE_PATH`, `OMNI_SECURITY_ISSUER`, `OMNI_COOKIES_SECURE`,
`OMNI_ALLOW_INSECURE_HTTP`, `OMNI_SETUP_TOKEN`, `OMNI_METRICS_TOKEN`,
`OMNI_SECURITY_RATE_LIMIT_WINDOW`, and `OMNI_UPLOADS_MAX_LOGO_BYTES`.

### Database backend

SQLite is the zero-config default and keeps the single-binary story. For
high-availability / multiple stateless instances behind a load balancer, use
**Postgres** (pure-Go pgx driver — no extra CGO):

```yaml
database:
  driver: postgres
  url: postgres://user:pass@db-host:5432/omni?sslmode=require
```

or `OMNI_DATABASE_DRIVER=postgres` + `OMNI_DATABASE_URL=...`. Migrations run
automatically on startup for whichever backend is configured. Run the Postgres
store integration test with `make test-postgres` (requires Docker), or set
`OMNI_TEST_POSTGRES_URL` and run `go test ./internal/store/ -run Postgres`.
SQLite-specific maintenance (`backup`, `integrity`) is not available on Postgres
— use native tooling (`pg_dump`, etc.).

### Passwords, activation & reset

- **Password rules** are admin-editable in **Admin → Settings**: minimum length
  plus require-uppercase / lowercase / number / symbol toggles, applied live
  everywhere a password is set.
- **New user picks their own password:** create a user with "Let the user choose
  their own password" to get a one-time, expiring **setup link** to hand over —
  no initial password needed.
- **Admin reset:** the per-user **Reset link** button issues a one-time reset
  link. Setting a password via any link revokes the account's existing sessions.
- **Self-service "Forgot password?":** enabled automatically when SMTP is
  configured (see `smtp` config). The login page shows a reset link; submissions
  are rate-limited and never reveal whether an account exists.

### Editable settings

The `security`, `cookies`, `uploads`, and identity (`issuer`/`public_url`) values above are
**seeded from config on first start**, then become editable from
**Admin → Settings** and apply **live** (no restart): token/refresh TTLs, lockout
threshold + duration, rate-limit window, pre-hash IP budget, password-verification
concurrency, login field caps, redirect URI loopback policy, password minimum
length, session lifetime + idle timeout, logo upload size, the cookie `Secure`
flag, and the issuer/public URL. A "Reset to config defaults"
action re-seeds from the current config. Infrastructure that binds at startup —
listen host/port, HTTP server timeouts/header limits, metrics/setup tokens, and
the database driver/url — stays config/env and is shown read-only. Changing the issuer/public URL invalidates existing tokens and
sessions; every settings change is written to the audit log.
Uploaded branding logos are limited to PNG, JPEG, or WebP files up to 512 KiB;
SVG is intentionally rejected because browsers treat it as active content.

> The `issuer` must be the public base URL clients use to reach the server; all
> discovery endpoint URLs are derived from it. Non-loopback `http://` issuer and
> public URLs are rejected unless `allow_insecure_http` / `OMNI_ALLOW_INSECURE_HTTP`
> is explicitly enabled.

### Directory / LDAP

Omni can authenticate users against an external **LDAP / Active Directory**
server, acting as an LDAP **client** (the standard pattern for an OIDC provider —
the same role Keycloak federation, Dex, and Authelia play). It is **off by
default**; enable it in the `ldap` config block (or `OMNI_LDAP_*` env vars).

How it works:

- **Search-then-bind.** Omni binds with a service account, searches `base_dn`
  with `user_filter` for the submitted username, then re-binds as that entry's DN
  with the submitted password to verify it. Filters are escaped (no LDAP
  injection) and bounded by size/time limits.
- **Schema presets.** `preset: activedirectory` or `openldap` fills in the
  standard filters and attributes (`sAMAccountName` / `inetOrgPerson`+`uid`,
  group object classes). Any field can be overridden explicitly.
- **Just-in-time provisioning.** On first successful login a local mirror account
  is created (`auth_source = ldap`, no local password) so sessions, OIDC codes,
  refresh tokens, and the audit log all key off it; the profile and admin flag are
  refreshed on every login.
- **Admin via group.** Members of `admin_group_dn` become Omni admins, re-checked
  each login.
- **MFA still applies.** A directory user who enrolls Omni TOTP is challenged for
  the second factor after the LDAP bind.
- **Local password flows are disabled** for directory accounts (forgot-password,
  set/reset link, change-password) — their password lives in the directory.
- The bind password is a **secret**: it is read from config/env only and is never
  shown in or settable from the web UI. **Admin → Settings** shows a read-only
  directory status panel; the users list marks each account's source.

#### Managing directory users (optional)

By default the LDAP integration is **read-only** — Omni authenticates against the
directory but does not modify it. To manage directory users from the admin panel,
configure a `bind_dn` that has **write** permission, then turn on **Admin →
Settings → System → Directory management** (the toggle appears once a write-capable
bind is configured; it applies live, no restart). `ldap.manage_enabled: true` in
config/env seeds that toggle on for fresh installs. The directory stays the
**source of truth**: each action is a single LDAP write, and Omni's local row
remains a thin mirror.

- **Create** a directory user from **Admin → Users** (Account type → *Directory
  user*): Omni issues an LDAP **Add** under `people_base_dn` (defaults to
  `base_dn`), named by `rdn_attr` (defaults to `attr_username`) with
  `user_object_classes` (defaults to the standard `inetOrgPerson` chain), then
  mirrors it locally so it appears immediately — no first login required.
- **Edit** email / display name (LDAP **Modify**), **set a password** (RFC 3062
  **PasswordModify**), and **delete** (LDAP **Delete**) from the user's page.
  Delete is **directory-first**: the entry is removed from the directory before
  the local mirror, so a failed write never orphans the directory entry.
- Guards: you cannot delete your own account or the last remaining administrator.
  Admin-ness for directory users still comes from `admin_group_dn`, not the panel.
- Targets **OpenLDAP / `inetOrgPerson`**. Active Directory write semantics,
  directory-side enable/disable, and promoting a local account into the directory
  are tracked as follow-ups; disable currently stays an Omni-layer control.

Pluggable by design: LDAP is the first `PasswordConnector`, so additional
external sources can be added behind the same login flow.

Pure-Go (`go-ldap/ldap/v3`), so the single-binary, no-extra-CGO story holds. To
run the gated LDAP integration test, set `OMNI_TEST_LDAP_URL` (plus the
`OMNI_TEST_LDAP_*` bind/base/user vars) and run `go test ./internal/ldap/`.

### Observability (logs & metrics)

- **Metrics** — `GET /metrics` exposes Prometheus text: HTTP request counts by
  status, plus identity series `omni_identity_logins_total{source,result}`,
  `omni_identity_mfa_total{result}`, `omni_identity_tokens_issued_total{type}`,
  the `omni_identity_active_sessions` gauge, and `omni_identity_build_info`. Point
  any Prometheus-compatible scraper (e.g. omni-metrics) at it.
- **Log shipping** — by default logs go to stdout as JSON. Set the `logging`
  block (`OMNI_LOGGING_*`) to *also* ship them to an [omnilog](https://github.com/pod32g/omni-logging)
  server: records are batched and POSTed to `/api/v1/ingest` (NDJSON, `X-Api-Key`)
  by a background worker. It is **best-effort and non-blocking** — if omnilog is
  slow or down, records are dropped rather than ever delaying or failing a
  request. The API key is a secret (config/env only).

## Run

```sh
./omni-identity serve -config config.yaml
```

On first launch, open the public URL — you'll be sent to `/setup` to create the
first administrator. If the public URL is not loopback, set `OMNI_SETUP_TOKEN`
or `security.setup_token` to a high-entropy one-time value and enter it on the
setup form. The wizard disables itself once an admin exists.

The binary also exposes operational subcommands used by the deploy pipeline:

```sh
omni-identity backup      --db ./omni-identity.db --out ./snapshot.db   # online VACUUM INTO
omni-identity integrity   --db ./omni-identity.db                       # PRAGMA integrity_check
omni-identity healthcheck --url http://localhost:8080/healthz          # 2xx = healthy
```

## Register a client (under 5 minutes)

1. Sign in to the admin UI and open **Applications**.
2. **Register application**: give it a name, choose a type, add the app's
   redirect URI(s), and pick scopes (`openid email profile offline_access`).
   - **confidential** (server-side apps like Jellyfin): a client secret is
     generated and shown **once** — copy it.
   - **public** (SPAs/native apps): no secret; the app must use PKCE.
3. Point the client at the OIDC endpoints below.

## OIDC endpoints

| Purpose | Path |
|---------|------|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| Revocation | `/oauth2/revoke` |
| UserInfo | `/userinfo` |
| JWKS | `/jwks.json` |
| Login / Logout | `/login`, `/logout` |
| Health / Metrics | `/healthz`, `/metrics` |

`/metrics` is disabled unless `metrics.bearer_token` or `OMNI_METRICS_TOKEN` is
set. Scrape it with `Authorization: Bearer <token>`.

## Integrating Jellyfin

Install the Jellyfin OIDC/SSO plugin and configure:

- **OIDC endpoint / discovery**: `https://identity.omni.local/.well-known/openid-configuration`
- **Client ID / Secret**: from the Applications page (confidential client)
- **Redirect URI**: the plugin's callback URL — add it to the client's redirect URIs
- **Scopes**: `openid profile email`

Jellyfin verifies tokens against the JWKS endpoint; RS256 is used by default for
broad compatibility.

## Integrating Omni Metrics / Omni Logging

Register each as a confidential client with its redirect URI and the scopes it
needs (`openid email` is usually sufficient). Use the standard Authorization
Code + PKCE flow and the discovery document above.

## Security notes

- Passwords are hashed with Argon2id; client secrets, authorization codes, and
  refresh tokens are stored hashed (never in plaintext).
- Access and ID tokens are stateless JWTs. Access tokens cannot be individually
  revoked — keep `token_ttl` short (default 15m); `/oauth2/revoke` invalidates
  refresh tokens, which stops renewal.
- Run behind HTTPS in production and keep `cookies.secure: true`.

## Deployment

Omni Identity ships with a Docker image (CGO SQLite on glibc distroless,
non-root, read-only rootfs) and a `docker compose` stack, plus a self-hosted
GitHub Actions pipeline that builds and deploys to a target host with
pre-deploy DB backup, integrity check, and auto-heal. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

```sh
make compose-up      # build + run locally via docker compose (uses .env)
```

## Non-goals (V1)

MFA, passkeys, LDAP, SAML, SCIM, social login, organizations, multi-tenancy,
complex RBAC, service accounts, API keys, audit-log UI, federation.

## License

TBD.
