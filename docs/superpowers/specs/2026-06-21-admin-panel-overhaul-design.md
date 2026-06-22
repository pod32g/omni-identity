# Admin Panel Overhaul — Design

**Date:** 2026-06-21
**Status:** Approved (design)
**Scope:** Presentation overhaul of the server-rendered admin UI (`internal/web/templates/`), plus one new read-only route. No authentication, authorization, or policy behavior changes.

## Problem

The admin panel looks bare in places and cramped in others:

- **Cramped:** the Users list crams up to five separate POST forms into a single Actions cell (Disable/Enable, Unlock, Reset 2FA, Reset link, and an inline "set password" field + button). On a populated row this wraps into a messy block. Inline form controls inside table cells fight the table layout.
- **Bare:** `/admin` redirects straight to Users with no at-a-glance overview; no empty states anywhere (an empty list shows only a header row); the Audit log is a plain event dump with no filters or grouping; Settings is one long column of stacked form panels.

The underlying design language in `internal/web/templates/base.html` is already refined (good tokens, spacing scale, components). Most of this work is applying it better and filling gaps — not a redesign of the visual language.

## Approach

Approach **B — list + detail pattern** (chosen over in-place-only refinement and over a client-side-JS rework):

- Fix the cramped Users page the right way by introducing a Users **detail page** (mirroring the existing Applications detail page) and moving per-user actions there.
- Fill the bare spots: a real dashboard, empty states, audit filters, and a navigable Settings page.
- Stay true to the existing architecture: **100% server-rendered, zero JavaScript** beyond a CSS-only `<details>` disclosure. No design-system (TypeScript) package changes — that is a separate library; this work is the Go template UI only.

## Constraints / guardrails

- No changes to auth, authorization, or security policy behavior — presentation only, plus one new **read-only GET** route (`GET /admin/users/{id}`).
- No JavaScript beyond native CSS `<details>` for the row overflow menu and Settings section nav anchors.
- All new styling is built from the existing CSS custom properties in `base.html` — no new colors or fonts.
- All existing POST endpoints and their handlers are reused unchanged; the Users detail page posts to the same routes the list does today.

## Components

### 1. Dashboard — new `/admin` landing

- `handleAdminHome` (currently a redirect to `/admin/users` at `internal/web/admin.go:57`) is changed to render a new `admin_dashboard.html`.
- **Stat cards** in a 4-up grid (`.stat-grid` / `.stat-card`):
  - Users — total, with disabled count as secondary.
  - Applications — total, with disabled count as secondary.
  - MFA adoption — percentage of local users with 2FA enabled.
  - Failed logins (last 24h) — derived from audit events.
- **Recent activity** panel: the last ~8 audit events with a "View all →" link to `/admin/audit`.
- **Setup nudges** shown only when relevant, e.g. "No applications registered yet" or "Secure cookies are off".
- Sidebar gains an **Overview** item at the top (new `ic-home` icon), marked active on the dashboard.

Data sources: counts and lists come from the existing user/client stores and the audit store the audit page already uses. No new persistence.

### 2. Users — uncramp the list, add a detail page

- **List** (`admin_users.html`): columns become Username (links to detail) · Email · Role · Source · Status chips · single trailing action. The trailing action is a `⋯` CSS `<details>` overflow menu (`.menu`) containing the quick Disable/Enable toggle and a "Manage →" link to the detail page. The inline password field is removed from the row.
- **New detail page** `admin_user_detail.html`, served at `GET /admin/users/{id}` via a new `handleAdminUserDetail` handler + route in `internal/web/server.go`. Layout mirrors `admin_client_detail.html`:
  - Identity header: username, email, role/status chips, "Back" to the list.
  - **Access** panel: role display, Enable/Disable form.
  - **Security** panel: Unlock (when locked), Reset 2FA (when enabled), Send reset link (local users).
  - **Password** panel: set-password form with full width.
  - Directory-managed users show the "managed by directory" note instead of local-only actions.
- All action forms post to the existing endpoints (`/admin/users/{id}/disable`, `/unlock`, `/mfa/reset`, `/reset-link`, `/password`). After a POST, redirect back to the detail page (existing handlers currently redirect to the list; they will be updated to redirect to the referring page / detail page where appropriate — a presentation-level redirect target change, not a behavior change).
- **Create user** form stays on the list page in its existing panel, width-capped, with breathing room.

### 3. Empty states — shared component

- New `{{define "empty-state"}}` partial in `base.html`: icon + title + one-line hint + optional action button, wrapped in `.empty`.
- Used on Users, Applications, and Audit when their lists are empty (and on Audit when a filter matches nothing). Example: Applications empty → "No applications yet · Register your first app to let it sign users in" with the register button.

### 4. Audit log — filters + readability

- **Filter bar** (`.filter-bar`) above the table: result (all / ok / fail), event-type `<select>`, and a free-text user/IP search box. All are plain GET query params parsed in `handleAdminAudit` (`internal/web/admin_security.go:27`); filtering happens server-side. No JS.
- Visual pass: event names as subtle monospace chips, clearer row rhythm, nowrap on the time column (already present). Empty state when no events match the active filter.
- Event-type options are derived from the known audit event names already emitted by the audit subsystem.

### 5. Settings — tame the wall of forms

- Keep the single page but add a **sticky in-page section nav** (`.section-nav`) down the left of the content column: anchor links to Identity · Tokens · Sessions · Account protection · Branding · System. Each existing panel gets a matching `id`.
- Group the read-only **Config/env status**, **Directory (LDAP)**, and **Endpoints** tables under one "System (read-only)" region so editable settings are visually separated from fixed ones.
- No change to which settings are editable or how they are saved.

### 6. Shared additions (in `base.html`)

- New CSS classes, all from existing tokens: `.stat-grid`, `.stat-card`, `.menu` (the `<details>` overflow menu), `.empty`, `.filter-bar`, `.section-nav`.
- New icon partials: `ic-home`, `ic-key`, `ic-lock`, `ic-search`, `ic-more`.

## Data flow

- Dashboard handler gathers: user list (for totals, disabled, MFA counts), client list (totals, disabled), and recent + last-24h audit events. All from existing stores; rendered into `admin_dashboard.html`.
- Users detail handler loads one user by `{id}` and renders `admin_user_detail.html`; 404 via the existing not-found path if the id is unknown.
- Audit handler reads filter query params, applies them server-side to the event list, and renders the filtered set plus the current filter state (to keep form selections sticky).

## Error handling

- Unknown user id on the detail route returns the existing 404/error rendering used elsewhere in the admin handlers.
- Invalid audit filter values fall back to defaults (treated as "all") rather than erroring.
- All existing form error/success alert rendering (`.alert error` / `.alert success`) is preserved on each page, including the new detail page.

## Testing

- Existing admin handler tests (`internal/web/admin_test.go`, `enterprise_test.go`, `settings_test.go`) must continue to pass.
- Add handler tests for: `handleAdminHome` now returns 200 with dashboard content (not a redirect); `handleAdminUserDetail` returns 200 for a known user and 404 for an unknown one; audit filter query params narrow the rendered event set.
- Template rendering is exercised through the handler tests (templates are parsed at startup; a parse error fails fast).

## Out of scope

- The `design-system/` TypeScript package.
- Any change to authentication, session, token, or rate-limit behavior.
- Pagination of the audit log (filtering only for now).
- Client-side interactivity (live search, sortable tables, modals, toasts).
