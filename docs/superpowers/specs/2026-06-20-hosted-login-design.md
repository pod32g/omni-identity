# Omni Identity — Hosted Login Experience (Design)

Date: 2026-06-20
Status: Approved

## Goal

Deliver an Omni Identity branded, hosted login experience for OIDC SSO,
comparable to Microsoft/Google/Okta. When a compatible app starts an
Authorization Code + PKCE flow, the user is redirected to a polished Omni
Identity `/login` page that shows the requesting application, authenticates the
user, and continues the authorization flow back to the app.

This is an **enhancement layer** on the existing OIDC provider. The
`/oauth2/authorize` validation (client_id, exact redirect_uri, scopes,
`response_type=code`, PKCE `S256`, state/nonce preservation, code issuance),
CSRF, generic login errors, secure cookies, and open-redirect protection
(`safeNext`) already exist and are retained.

## Decisions (from brainstorming)

- **Branding**: stored in SQLite, edited via `/admin/settings`, logo **uploaded**
  (stored as a blob in the DB, served from a route). Keeps deployments stateless.
- **Consent**: per-client `skip_consent` flag. Trusted/first-party clients skip
  consent; others see a consent screen. (Covers Option A and B.)
- **Logout**: full RP-initiated logout — validate `id_token_hint`, allowlist
  `post_logout_redirect_uri` per client, preserve `state`, clear session, revoke
  the user+client's refresh tokens.
- **Pending request**: server-side stored `auth_requests` row keyed by an opaque
  id, replacing the `next=<url>` redirect approach.

## Data model & migrations

New migration `0003_branding_metadata.sql`:

1. **Extend `clients`** (all nullable / defaulted, backward compatible):
   - `display_name TEXT NOT NULL DEFAULT ''`
   - `logo_url TEXT NOT NULL DEFAULT ''`
   - `homepage_url TEXT NOT NULL DEFAULT ''`
   - `post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]'` (JSON array)
   - `skip_consent INTEGER NOT NULL DEFAULT 1`

2. **`branding`** — single row (`id INTEGER PRIMARY KEY CHECK (id = 1)`):
   - `product_name TEXT NOT NULL DEFAULT 'Omni Identity'`
   - `logo_blob BLOB`, `logo_content_type TEXT NOT NULL DEFAULT ''`
   - `accent_color TEXT NOT NULL DEFAULT ''`
   - `footer_text TEXT NOT NULL DEFAULT ''`
   - `background_style TEXT NOT NULL DEFAULT ''`
   - `updated_at TIMESTAMP NOT NULL`

3. **`auth_requests`** — pending authorization requests:
   - `id TEXT PRIMARY KEY` (opaque, 32-byte random)
   - `client_id, redirect_uri, scope, state, nonce, response_type` TEXT
   - `code_challenge, code_challenge_method` TEXT
   - `created_at, expires_at TIMESTAMP` (TTL ~10 min)
   - index on `expires_at`

Model additions mirror these in `internal/model`.

## Authorize flow (`authorize_handler.go`)

Validation order unchanged: client → exact redirect_uri → `response_type=code`
→ scope (openid required, subset of allowed) → PKCE (`code_challenge` required
for public clients; method must be `S256` when present).

After validation:
- Look up current session.
- **Authenticated + `skip_consent`** (or consent already granted): issue code
  immediately and redirect to `redirect_uri` with `code` and `state`
  (existing behavior, refactored into `issueCodeAndRedirect`).
- **Authenticated + needs consent**: persist an `auth_request`, redirect to
  `/consent?req=<id>`.
- **Unauthenticated**: persist an `auth_request`, redirect to `/login?req=<id>`.

`/login` and `/consent` load the stored request by id. On success they **resume**
by calling `issueCodeAndRedirect` with the already-validated stored request. The
`auth_request` is single-use: deleted after a code is issued, and expired rows
are ignored (→ "expired authorization request" error page).

`next=` (same-origin path) is retained for plain admin login (no `req`).

## Hosted login page

Restyle `login.html`:
- When `req` is present: header "Sign in to continue to **<App display name>**",
  app logo (`logo_url`), and the app domain (host of `redirect_uri`).
- When no `req`: today's generic "Sign in to continue." copy (admin login).
- Omni branding (product name, logo, accent, footer) from the `branding` row.
- Email/username + password, CSRF token, preserves `req`/`next` in a hidden field.

## Consent screen (`/consent`)

Only reached when client `skip_consent = 0`.
- Shows app name, the signed-in user identity (username/email), and requested
  scopes rendered human-readably (e.g. `profile` → "Your profile information").
- Continue (POST, CSRF) → `issueCodeAndRedirect`.
- Cancel → `redirectErr(redirect_uri, "access_denied", ...)`.

## Logout (`/logout`)

`GET /logout` (RP-initiated):
- Parse optional `id_token_hint`; verify signature against JWKS + issuer; extract
  `sub` and `aud` (client_id). Invalid hint → ignore identity, still clear session.
- Clear the Omni session cookie + delete the session row.
- If `id_token_hint` identified a user+client, revoke that pair's refresh tokens
  (`RevokeRefreshTokensForUserClient`).
- If `post_logout_redirect_uri` is present and **exactly** matches the client's
  allowlist, redirect there with `state`; otherwise render a branded
  "You've signed out of Omni Identity" page.

`POST /logout` (existing, CSRF) is retained for the admin nav button and now
renders the same signed-out page.

## Branding service (`internal/branding`)

- `Service` loads and caches the `branding` row; `Reload()` after admin save.
- Exposes a `View` (product name, logo URL `/branding/logo` or empty, accent
  color, footer text, background style) injected into the base template data for
  login, setup, consent, logout, error pages.
- `GET /branding/logo` serves the stored blob with its content type (404 if none).
- Admin `/admin/settings` becomes editable: a form (product name, accent, footer,
  background) + multipart logo upload. CSRF-protected, admin-only. Validates
  content type (png/jpeg/svg/webp) and size (≤ 512 KB). Accent color validated as
  a CSS color token (hex/oklch); invalid → field error.

## Security additions

- **Rate limiting** (`internal/web/ratelimit.go`): in-memory, per
  (client IP + submitted username) fixed-window/token-bucket limiter, e.g. 5
  failed attempts per 15 min → generic "too many attempts" error, HTTP 429.
  Successful login resets the counter. Bounded map with periodic cleanup.
- **Session rotation**: on successful login (and setup), delete any pre-existing
  session for the request cookie before issuing the new one (`SessionManager`
  gains a rotate path), preventing session fixation. The new session already gets
  a fresh random id + CSRF secret.
- Retained: generic auth errors, exact redirect matching, no wildcard redirects,
  `safeNext`, HttpOnly + Secure + SameSite=Lax cookies.

## Friendly error pages

`renderError` continues to render a branded `error.html` (now branding-aware).
Add a typed helper `renderOIDCError(w, r, status, userMsg, logDetail, err)` that
logs full detail server-side via `slog` and shows friendly copy for: invalid
client, invalid redirect_uri, invalid scope, missing PKCE, expired/unknown auth
request, login failed, access denied.

## Integration docs (`docs/INTEGRATION.md`)

- How an external app starts Authorization Code + PKCE (endpoints, params,
  `code_verifier`/`code_challenge` derivation, token exchange).
- A reusable **"Continue with Omni Identity"** button: HTML + CSS snippet and a
  minimal JS PKCE starter that performs the redirect. Alternative label
  "Sign in with SSO". Emphasizes: no passwords collected in the client app.

## Client metadata in admin UI

Extend the client create/detail forms and store layer to manage `display_name`,
`logo_url`, `homepage_url`, `post_logout_redirect_uris`, and `skip_consent`
alongside the existing `name`, `type`, `redirect_uris`, `allowed_scopes`.

## Testing

Table-driven Go tests (httptest) covering:
- App → `/oauth2/authorize` validation (happy path issues code).
- Unauthenticated user redirected to `/login?req=…`.
- Login preserves the stored auth request and resumes it.
- Successful login redirects back to `redirect_uri` with `code` + `state`.
- Existing session + `skip_consent` skips login and issues code directly.
- Invalid redirect_uri rejected (branded error, no redirect).
- Missing PKCE for public client rejected.
- CSRF failure on login rejected (403).
- Login rate limiting trips after N attempts (429).
- Consent allow issues code; consent cancel returns `access_denied`.
- Logout clears the session cookie, revokes refresh tokens for the
  `id_token_hint` user+client, and validates `post_logout_redirect_uri`.
- Branding row drives rendered product name; logo route serves blob.

## Out of scope (V1)

- Social / external IdP federation.
- Per-scope granular consent revocation UI.
- Remember-device / MFA.
- Multi-tenant branding (single global branding row only).
```