# Omni Identity — Password Policy & Reset Flows

Date: 2026-06-20
Status: In progress

Three connected features sharing one secure token mechanism.

## M1 — Configurable password complexity (live settings)

Add admin-editable toggles to the live settings: `require_upper`,
`require_lower`, `require_number`, `require_symbol` (alongside the existing
`password_min_length`). Refactor `auth.ValidatePassword` to take a
`PasswordPolicy{MinLength, RequireUpper, RequireLower, RequireNumber,
RequireSymbol}` and enforce it everywhere a password is set (setup wizard, admin
create/set, account change, and the new set-password page). Defaults preserve
current strength: min 12 + a number required.

## M2 — One-time activation & reset links (admin-initiated)

New `password_tokens` table: `id, user_id, token_hash (unique), purpose
('activation'|'reset'), used, expires_at, created_at`. Tokens are 32-byte
random, hashed at rest, single-use, expiring (activation 72h, reset 1h).

- **Create user → setup link:** admin can create a user with no usable password
  (empty hash → password login always fails) and get a one-time
  `/set-password?token=…` link to copy and hand over.
- **Reset password → link:** a per-user admin action issues a reset token + link.
- **Set-password page** (`/set-password`): validates the token, shows a form
  honoring the live complexity policy, sets the password, **consumes the token,
  deletes the user's other password tokens, and revokes all their sessions**,
  then redirects to `/login` with a success flash (no auto-login → avoids any
  MFA bypass).

## M3 — Self-service forgot-password (SMTP)

- **Config (infra, not web-editable):** `smtp.host/port/username/password/from/
  starttls` + `OMNI_SMTP_*` env. Self-service auto-enables when host+from are set.
- **`internal/email`:** a small `Sender` interface (SMTP impl via stdlib
  `net/smtp`; a no-op/mock for tests). Builds a plain-text reset email.
- **`/forgot`:** GET form (enter email/username) + POST. On POST, if the account
  exists, mint a reset token and email the link; **always** return the same
  generic response (no user enumeration), and rate-limit by IP. Reuses the M2
  set-password page to complete.
- **Login page:** a "Forgot password?" link, shown only when self-service is
  enabled.

## Cross-cutting

- Migration `0006` (SQLite + Postgres): settings complexity columns +
  `password_tokens` table.
- Audit events: `user.invited`, `password.reset_requested`,
  `password.reset_link_issued`, `password.set_via_token`.
- Security: token entropy + hashing + single-use + expiry; session revocation on
  password change; generic `/forgot` response; rate limiting; SMTP creds never
  rendered in the UI; set-password enforces the live policy.

## Tests

Policy validation matrix; token issue/consume/expire/single-use; create-user
activation link flow; admin reset link flow; set-password enforces policy +
revokes sessions; `/forgot` is enumeration-safe and emails via a mock sender;
SMTP-disabled hides the link; Postgres parity for the new table/columns.
