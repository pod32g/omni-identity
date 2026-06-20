# Omni Identity — Live Editable Settings (admin panel)

Date: 2026-06-20
Status: In progress

Goal: make operational/security settings editable from `/admin/settings` and
applied **live** (no restart), backed by the database.

## Storage & precedence

New single-row `settings` table (migration `0005`, SQLite + Postgres variants),
like `branding`. Seeded **once** from the loaded config/env on first start
(`seeded` flag), after which the DB row is authoritative for the editable
settings and the admin panel edits it. A "Reset to config defaults" action
re-seeds from the current config. (Documented tradeoff: once seeded, env changes
to these fields no longer override the DB.)

## Editable (live)

issuer, public_url, token_ttl, refresh_token_ttl, max_failed_logins,
lockout_duration, password_min_length, session_idle_timeout, session_lifetime,
cookie_secure.

## Read-only (boot-bound, displayed with a note)

server host/port and database driver/url — these bind the HTTP listener and the
store at startup and cannot change at runtime.

## Live mechanism — a settingsService

`internal/web/settings.go`: a cached, thread-safe service (like
`brandingService`) that is the live source of truth. It implements two small
provider interfaces so the long-lived objects read settings at use-time:

- `tokens.IssuerConfig` (Issuer string, AccessTTL, IDTTL) — the token Issuer
  gains `SetConfigProvider`; when set it reads issuer/TTLs from the service at
  issue and verify time (existing static `NewIssuer` unchanged for tests).
- `auth.SessionConfig` (Secure, Lifetime, IdleTimeout) — the SessionManager
  gains `SetConfigProvider`; when set it reads cookie Secure, session lifetime,
  and idle timeout live (existing static constructor unchanged for tests).

Other consumers read the service directly:
- lockout + password policy handlers (already per-request): switch `cfg` → service.
- cookie Secure for CSRF cookies + HSTS: `s.cookieSecure()` → service.
- discovery: issuer/public_url → service.

## Guardrails

- Validation: durations must parse; `password_min_length >= 8`;
  `max_failed_logins >= 1`; `refresh_token_ttl >= token_ttl`; TTLs within sane
  bounds. Invalid input re-renders with an error and persists nothing.
- UI warnings on dangerous changes: changing issuer/public_url invalidates all
  existing tokens & sessions; disabling cookie Secure weakens security.
- Every change written to the audit log (`admin.settings.updated`); admin-only;
  CSRF-protected.

## Admin UI

`/admin/settings` grows grouped editable sections — Identity, Tokens, Sessions &
cookies, Account protection — alongside the existing Branding section, plus the
read-only infra panel for reference and a "Reset to config defaults" button.

## Tests

- Settings round-trip + seeding in the store.
- Live application: changing token_ttl changes `expires_in`; lowering
  max_failed_logins changes lockout threshold; toggling cookie_secure changes the
  session cookie Secure flag; changing issuer changes discovery + new id_token iss.
- Validation rejects bad input (short password floor, refresh < token, unparized
  duration) without persisting.
- Postgres variant covered by the existing env-gated integration test pattern.
