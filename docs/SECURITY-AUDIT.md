# Omni Identity — Security Audit

Date: 2026-06-20
Scope: the enterprise-hardening branch (audit logging, account lockout, AES-GCM
encryption of TOTP secrets, TOTP MFA, OIDC introspection, `client_credentials`,
`prompt`/`max_age`, self-service account, HSTS, password policy, idle timeout)
on top of the existing hosted-login OIDC provider.

Methodology: automated security review of the full branch diff (identification
pass + independent false-positive filtering), plus manual data-flow tracing from
user input to sensitive sinks across the auth, MFA, token, account, store, and
template layers. Findings rated below confidence 8/10 were dropped.

## Findings

### F-1 (HIGH, fixed) — Token introspection leaked other clients' token metadata

`POST /oauth2/introspect` authenticated the caller as any confidential client
but did not verify that the introspected token belonged to that client. A
confidential client could submit another client's access or refresh token and
learn the end-user `sub`, granted `scope`, `client_id`/`aud`, and `exp` —
broken access control / cross-tenant information disclosure (RFC 7662 §4). The
sibling revoke endpoint already enforced this ownership invariant.

Fix: `internal/web/introspect_handler.go` now requires the access token's
audience to equal the calling client, and the refresh token's `client_id` to
equal the calling client; otherwise it returns `{"active": false}` without
disclosing the token's existence. Regression test:
`TestIntrospectionRejectsOtherClientsToken`.

### F-2 (LOW, fixed) — Recovery-code entropy reduced by lossy normalization

Recovery codes were generated from a case-sensitive base64url alphabet but
normalized (lowercased, `-` stripped) before hashing, reducing effective entropy
and risking ambiguity. Brute force was already impractical (single-use codes +
per-user MFA rate limiting), so this was defense-in-depth.

Fix: codes are now 64-bit hex (`auth.RandomHex(8)`), grouped as
`xxxx-xxxx-xxxx-xxxx`; the hex alphabet is case-insensitive and dash-free, so
normalization is lossless and full entropy is preserved.

## Areas reviewed — no actionable vulnerability

- **MFA cannot be skipped.** The password step issues no session when
  `user.MFAEnabled`; it parks a server-side `login_challenges` row keyed to the
  user and sets an opaque 32-byte challenge cookie. `/login/mfa` reloads the
  challenge, re-fetches the user, re-checks `MFAEnabled`/`Disabled`, then issues
  the session (`amr="pwd mfa"`). Challenges are single-use and expire in 5 min.
- **Client-auth on `client_credentials`, introspection, and revoke** is
  restricted to authenticated confidential (non-public) clients;
  `client_credentials` excludes `openid` and enforces requested scope ⊆ allowed.
- **`prompt=none` / `max_age`** return `login_required`/`consent_required`
  without UI and force re-auth based on session auth-time. No bypass.
- **Account lockout** is checked before password verification, resets on
  success, and is admin-clearable; it complements per-IP rate limiting.
- **Self-service `/account`** has no IDOR — every handler acts on the session's
  user/session, never a request-supplied id. All state-changing POSTs validate a
  constant-time double-submit CSRF token. Password change re-authenticates and
  revokes other sessions; disabling a user / changing a password revokes
  sessions server-side. `requireAdmin` vs `requireUser` are correctly separated.
- **Crypto.** AES-256-GCM uses a fresh random nonce per encryption (no reuse);
  the app key is 32 bytes from `crypto/rand`. TOTP verification is constant-time
  with ±1 step skew and matches RFC 6238 vectors.
- **SQL injection.** All new store methods use parameterized `?` placeholders;
  column-list constants contain no user input.
- **XSS.** New templates render all dynamic values (including attacker-influenced
  user-agent and audit detail) through Go `html/template`'s default contextual
  auto-escaping; no `template.HTML`/`JS`/`URL` safe types and no injection into
  `<script>`/`<style>`/unquoted-URL sinks. The admin-only `accent_color` and
  `background_style` branding fields, which *are* rendered into a `<style>`
  block, are validated/character-restricted before storage.

## Residual notes (accepted)

- **Lockout is observable.** A locked account returns a distinct "temporarily
  locked" message, which reveals account existence to an attacker who has already
  triggered the lockout. This is standard enterprise UX (Okta/Azure AD behave the
  same) and is bounded by per-IP rate limiting; accepted for V1.
- **No backchannel/front-channel logout, WebAuthn, or email flows** (verification
  / reset) — out of scope for this pass (no SMTP dependency).

## Verification

`go build ./...`, `go vet ./...`, and `go test ./...` pass after remediation,
including the new `TestIntrospectionRejectsOtherClientsToken` regression test.
