# Promote a local user into LDAP (phase 2)

**Date:** 2026-06-22
**Status:** Approved direction (`/goal let's work on that`)
**Builds on:** `2026-06-21-ldap-user-management-design.md` (Option 1, LDAP-canonical)

## Problem

A user that started as a **local** Omni account (`auth_source=local`, local
password hash) cannot be turned into a directory-backed account. Creating a
directory user with the same username is actively refused
(`UpsertExternalUser` collision guard), so there is no path to "sync this local
user with LDAP."

## Decision

Add a **one-shot, admin-triggered promote** action. It is not continuous sync —
after promotion LDAP is canonical for that user and nothing reconciles on a
schedule. Two sub-cases, auto-detected:

1. **Link** — a directory entry already exists for the username → associate the
   Omni row with that entry's DN (no LDAP write to the entry).
2. **Create + link** — no entry exists → LDAP Add a new entry, optionally set an
   admin-supplied password, then link.

After either: the Omni row flips `auth_source=local → ldap`, stores
`external_id = DN`, and clears `password_hash` (Omni no longer owns the
credential). Omni-only state (MFA enrollment, lockout) is preserved. Active
sessions are revoked so the next login goes through the directory bind.

## Design

### Connector: lookup (internal/ldap, authn.DirectoryManager)

Add `LookupDN(ctx, username) (dn string, found bool, err error)` to
`DirectoryManager`. The LDAP implementation reuses the existing service-bind +
`findUser` search and returns the matched entry's DN (found=false on zero/many
matches, mirroring the auth path). This drives the link-vs-create decision.

### Store (internal/store)

Add `LinkUserToExternal(ctx, id, source, externalID string) error`: sets
`auth_source`, `external_id`, clears `password_hash`, bumps `updated_at`. The
existing unique index on `(auth_source, external_id)` guards against linking two
Omni rows to the same DN.

### Handler (internal/web)

`POST /admin/users/{id}/promote` (`handleAdminPromoteUser`):

1. CSRF + admin gate. Load the user; must be `IsLocal()`, else error.
2. `dir := s.directoryManager()`; nil → "management not enabled".
3. `dn, found, _ := dir.LookupDN(ctx, user.Username)`.
4. If not found → `dn, err = dir.CreateUser(ctx, DirectoryUser{username, email,
   displayName})`; if a password was supplied, `dir.SetPassword(ctx, dn, pw)`
   (policy-validated first).
5. `s.db.LinkUserToExternal(ctx, user.ID, dir.ID(), dn)`.
6. Revoke the user's sessions; audit `admin.user.promoted`.

Directory-first: the entry must exist (found or created) before the Omni row is
re-pointed. A create failure leaves the local account untouched.

### UI (admin_user_detail.html)

For a **local** user when management is enabled, a "Promote to directory" panel:
optional directory-password field + submit. Hidden for already-directory users
and when management is off.

## Guards / edge cases

- Local-only action: promoting a non-local user is rejected.
- Username collision on link is impossible (same row keeps its username); the
  unique external-id index catches double-linking.
- If create succeeds but the password set fails, surface it — the entry exists
  and the admin can set a password from the (now directory-backed) user page.

## Testing

- `internal/ldap`: `LookupDN` interface compliance (search covered by existing
  integration test).
- `internal/store`: `LinkUserToExternal` flips source/external_id and clears the
  hash; double-link errors.
- `internal/web` (fake `DirectoryManager` + `LookupDN`): promote-creates (no
  existing entry, password set, row re-pointed, hash cleared, sessions gone),
  promote-links (existing entry, no Add/SetPassword), local-only guard,
  management-off guard.

## Out of scope

Continuous sync, group/role mapping, AD-specific write semantics, demotion
(directory → local). Follow-ups if needed.
