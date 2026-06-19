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
- Signed JWTs (RSA **RS256** default, plus Ed25519 **EdDSA**) published via JWKS
- Discovery endpoint (`/.well-known/openid-configuration`)
- Browser sessions with CSRF-protected forms and secure cookies
- Minimal admin UI: users, applications (clients), settings
- First-run web wizard to create the initial admin
- Token revocation (RFC 7009) for refresh tokens
- Structured request logging and a basic Prometheus-style `/metrics` endpoint
- Single binary + SQLite

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
  path: ./omni-identity.db

security:
  issuer: https://identity.omni.local        # defaults to public_url
  token_ttl: 15m
  refresh_token_ttl: 720h

cookies:
  secure: true                                # set false for local http:// dev
```

Any value can be overridden by environment variables, e.g. `OMNI_SERVER_PORT`,
`OMNI_DATABASE_PATH`, `OMNI_SECURITY_ISSUER`, `OMNI_COOKIES_SECURE`.

> The `issuer` must be the public base URL clients use to reach the server; all
> discovery endpoint URLs are derived from it.

## Run

```sh
./omni-identity -config config.yaml
```

On first launch, open the public URL — you'll be sent to `/setup` to create the
first administrator. The wizard disables itself once an admin exists.

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

## Non-goals (V1)

MFA, passkeys, LDAP, SAML, SCIM, social login, organizations, multi-tenancy,
complex RBAC, service accounts, API keys, audit-log UI, federation.

## License

TBD.
