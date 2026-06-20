# Omni Identity — Enterprise Hardening Plan

Date: 2026-06-20
Status: In progress

Goal: bring Omni Identity as close as practical to an enterprise-grade OIDC
identity provider without introducing external service dependencies (no SMTP,
no third-party IdP), then perform a full security audit.

All work uses the existing SQLite store, Go stdlib + already-vendored crypto,
and the established handler/template patterns. Each milestone ships with tests
and is committed independently. `go build`, `go vet`, and `go test ./...` stay
green throughout.

## Milestones

- [ ] **M1 — Audit logging.** `audit_log` table + `internal/audit` recorder.
  Record auth events (login success/failure, lockout, logout, consent
  allow/deny, MFA enroll/verify), token events (code/refresh/client_credentials
  issuance, revocation), and admin actions (user + client + branding changes).
  Admin `/admin/audit` viewer.

- [ ] **M2 — Account lockout.** `failed_login_count` + `locked_until` on users.
  Lock after N consecutive failures (config, default 5) for a cooldown
  (default 15m). Reset on success. Admin unlock on the user row. Generic user
  messaging preserved (no enumeration). Complements per-IP rate limiting.

- [ ] **M3 — App secret + AES-GCM crypto.** `app_secrets` single-row table
  holding an auto-generated 32-byte key. `internal/crypto` AES-256-GCM helper to
  encrypt secrets at rest (used for TOTP secrets).

- [ ] **M4 — TOTP MFA.** RFC 6238 TOTP (self-implemented, no dep). Per-user
  enrollment via self-service `/account`, encrypted secret at rest, 10 hashed
  single-use recovery codes. Login second factor (`/login/mfa`) with a
  short-lived DB challenge, rate-limited. `amr`/`auth_time` reflected in the ID
  token. Admin can see MFA status and reset it.

- [ ] **M5 — OAuth/OIDC completeness.** `/oauth2/introspect` (RFC 7662),
  `client_credentials` grant, `prompt=none|login` and `max_age` handling in
  authorize. Discovery advertises the new endpoint, grant, and prompt values.

- [ ] **M6 — Self-service account.** `/account`: change own password (re-auth),
  list active sessions, "sign out everywhere", manage MFA.

- [ ] **M7 — Hardening.** HSTS (when cookies.secure), configurable password
  policy (min length, reject username/email match), session idle timeout +
  absolute lifetime, token-endpoint hygiene.

- [ ] **M8 — Security audit.** Full review (security-review skill + manual),
  written report at `docs/SECURITY-AUDIT.md`, fix confirmed findings, re-verify.

## Cross-cutting schema (migration 0004)

- `audit_log(id, created_at, event, actor_user_id, username, client_id, ip,
  user_agent, success, detail)` + index on created_at.
- `users`: `failed_login_count INTEGER DEFAULT 0`, `locked_until TIMESTAMP NULL`,
  `mfa_enabled INTEGER DEFAULT 0`, `totp_secret TEXT DEFAULT ''` (AES-GCM
  ciphertext, base64).
- `mfa_recovery_codes(id, user_id, code_hash, used, created_at)`.
- `login_challenges(id, user_id, next, req, created_at, expires_at)` — pending
  MFA step.
- `app_secrets(id=1, key_b64, created_at)`.
- `sessions`: `last_seen_at TIMESTAMP NULL`, `amr TEXT DEFAULT ''`.

## Non-goals (this pass)

Email flows (verification, reset) — no SMTP. External IdP federation. SCIM.
WebAuthn/passkeys. Multi-tenant orgs.
