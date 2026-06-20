# Omni Identity

> Boring identity for private infrastructure.

A small, self-hosted OpenID Connect (OIDC) identity provider. It lets Omni
services and standards-compatible third-party apps (e.g. Jellyfin) authenticate
users through a single Omni Identity login. Private by default, self-hosted
first, one binary, SQLite.

## Features (V1)

- Local users with Argon2id password hashing
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

database:
  driver: sqlite                              # sqlite (default) or postgres
  path: ./omni-identity.db                    # used when driver = sqlite
  url: ""                                      # postgres DSN when driver = postgres

security:
  issuer: https://identity.omni.local        # defaults to public_url
  token_ttl: 15m
  refresh_token_ttl: 720h

cookies:
  secure: true                                # set false for local http:// dev
```

Any value can be overridden by environment variables, e.g. `OMNI_SERVER_PORT`,
`OMNI_DATABASE_PATH`, `OMNI_SECURITY_ISSUER`, `OMNI_COOKIES_SECURE`.

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

### Editable settings

The `security`, `cookies`, and identity (`issuer`/`public_url`) values above are
**seeded from config on first start**, then become editable from
**Admin → Settings** and apply **live** (no restart): token/refresh TTLs, lockout
threshold + duration, password minimum length, session lifetime + idle timeout,
the cookie `Secure` flag, and the issuer/public URL. A "Reset to config defaults"
action re-seeds from the current config. Infrastructure that binds at startup —
listen host/port and the database driver/url — stays config/env and is shown
read-only. Changing the issuer/public URL invalidates existing tokens and
sessions; every settings change is written to the audit log.

> The `issuer` must be the public base URL clients use to reach the server; all
> discovery endpoint URLs are derived from it.

## Run

```sh
./omni-identity serve -config config.yaml
```

On first launch, open the public URL — you'll be sent to `/setup` to create the
first administrator. The wizard disables itself once an admin exists.

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
