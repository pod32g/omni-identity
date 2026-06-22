# LDAP User Management (Option 1: LDAP-canonical)

**Date:** 2026-06-21
**Status:** Approved direction (`/goal implement option 1`)

## Problem

Directory (LDAP) users are not manageable through Omni today. Omni acts only as
an LDAP *client for authentication* — it searches + binds to verify a password,
and lazily creates a thin local "shadow" row on first login
(`UpsertExternalUser`). Admins cannot create, edit, delete, or set passwords for
directory users from the Omni admin panel.

## Decision: Option 1 — LDAP is the source of truth

Omni becomes a **management UI on top of the directory**. Each lifecycle action
is a single LDAP write against the directory using the (now privileged) service
account:

- **Create** → LDAP Add
- **Edit attributes** → LDAP Modify
- **Set/reset password** → LDAP Password Modify (RFC 3062 extended op)
- **Delete** → LDAP Delete

Omni's local DB stays a thin shadow used only for what the directory can't hold
(MFA enrollment, lockout counters, session state). No bidirectional sync engine:
every write either succeeds against the directory or visibly fails. The shadow
row is reconciled immediately after a successful directory write and, as today,
on next login.

### Rejected: Option 2 (Omni-canonical, push to LDAP)

Would require a sync/reconciliation engine (conflict resolution, drift repair,
retry/backfill). Only worth it if Omni were to *become* the primary store and
demote LDAP to a downstream replica — not the goal here.

## Scope

### Phase 1 (this spec)

Write set for **OpenLDAP / `inetOrgPerson`** (matches the test directory),
structured so Active Directory can be added later:

1. **LDAP write methods** on the connector: Add, Modify, Delete, Password-Modify.
2. **Create directory user** from the admin panel (LDAP Add + shadow row).
3. **Set/reset password** for a directory user (LDAP Password Modify) — unblocks
   the current "managed by external directory" refusal for *managed* directories.
4. **Edit directory user** attributes (email, display name) — LDAP Modify +
   shadow refresh.
5. **Delete user** (directory: LDAP Delete + shadow removal; local: shadow
   removal) — new capability, with safety guards.
6. **UI**: create form gains a "directory user" path; detail page exposes
   edit / set-password / delete for directory users **when management is
   enabled**; otherwise the existing read-only notes stand.
7. **Audit** events for every directory write.

### Explicitly deferred (documented, not built here)

- **Active Directory write semantics** (cleartext `unicodePwd` over LDAPS,
  `userAccountControl` for disable). Phase 1 targets OpenLDAP; the write
  interface is flavor-agnostic so AD slots in behind it.
- **Writing enable/disable into the directory.** OpenLDAP has no standard
  "disabled" flag. Disable stays an Omni-layer control (Omni performs the bind,
  so a disabled shadow blocks login through Omni). Documented limitation.
- **Promote a local user into LDAP** (one-shot Add + link, admin sets the
  directory password). Clean phase-2 add-on; sequenced after core CRUD.
- **Group/role membership management.**

## Design

### 1. Directory management capability

Management requires a single, privileged directory target — distinct from the
`[]authn.PasswordConnector` auth slice. Define a capability interface the LDAP
`Client` also implements:

```go
// authn.DirectoryManager is implemented by connectors that can write to their
// backing directory. Optional: nil when no managed directory is configured.
type DirectoryManager interface {
    ID() string
    CreateUser(ctx context.Context, spec DirectoryUser) (dn string, err error)
    SetPassword(ctx context.Context, dn, password string) error
    UpdateUser(ctx context.Context, dn string, attrs DirectoryUser) error
    DeleteUser(ctx context.Context, dn string) error
}

type DirectoryUser struct {
    Username    string
    Email       string
    DisplayName string // cn
    Surname     string // sn (required by inetOrgPerson; defaulted if empty)
}
```

`Server` gains `directory authn.DirectoryManager` (nil unless
`cfg.LDAP.Enabled && cfg.LDAP.ManageEnabled`). Handlers check `s.directory != nil`
to decide whether management actions are offered/allowed.

### 2. LDAP write implementation (`internal/ldap`)

Add methods to `Client`, each opening a connection and binding as the service
account (reusing `dial()`), then issuing the write:

- **CreateUser**: build DN `<RDNAttr>=<username>,<PeopleBaseDN>` (RDN value
  escaped via `goldap.EscapeDN`); `AddRequest` with `objectClass` =
  configured classes and attributes `uid`, `cn`, `sn`, `mail`. Returns the DN.
- **SetPassword**: `goldap.PasswordModifyRequest{UserIdentity: dn,
  NewPassword: pw}` over the existing TLS/StartTLS connection.
- **UpdateUser**: `ModifyRequest` replacing `mail` / `cn` as provided.
- **DeleteUser**: `DelRequest{DN: dn}`.

Reuse `EscapeFilter`/escaping already present; never interpolate raw user input
into DNs or filters.

### 3. Config (`internal/config`)

New `LDAPConfig` fields (env-overridable, same pattern as existing fields):

| Field | YAML | Default | Purpose |
|-------|------|---------|---------|
| `ManageEnabled` | `manage_enabled` | `false` | Opt-in to write management |
| `PeopleBaseDN` | `people_base_dn` | `BaseDN` | Parent DN for new entries |
| `RDNAttr` | `rdn_attr` | `AttrUsername` (`uid`) | RDN attribute for new entries |
| `UserObjectClasses` | `user_object_classes` | `[top, person, organizationalPerson, inetOrgPerson]` | objectClasses on Add |

Validation (only when `ManageEnabled`): require a non-anonymous `BindDN` (writes
need a privileged bind) and a usable `PeopleBaseDN`. Presets may later carry an
AD object-class default.

### 4. Store (`internal/store`)

Add `DeleteUser(ctx, id) error` (hard delete of the shadow row). Sessions are
cleared first via the existing `DeleteSessionsForUser`. Audit rows store the
username/actor as plain strings (no FK), so deletion is safe.

### 5. Handlers (`internal/web/admin_directory.go`, new file)

- `handleAdminCreateUser` ([admin.go:195](../../internal/web/admin.go)) branches
  on a `source` form value: `local` (today's flow) vs `ldap`. The `ldap` branch
  calls `s.directory.CreateUser`, then provisions the shadow via
  `UpsertExternalUser`, then optionally sets an initial password.
- `handleAdminUpdateDirectoryUser`: LDAP Modify + `UpdateUser` shadow refresh.
- `handleAdminDeleteUser` (POST `/admin/users/{id}/delete`): for directory users
  → `s.directory.DeleteUser(dn)` then `db.DeleteUser`; for local users →
  `db.DeleteUser`. Guards: cannot delete self; cannot delete the last enabled
  admin (`CountAdmins`).
- `handleAdminUserPassword`: for directory users with management enabled, route
  to `s.directory.SetPassword` instead of the local-hash path; the existing
  `IsLocal()` block in [password_reset_handler.go](../../internal/web/password_reset_handler.go)
  stays for *unmanaged* directories.

All new POSTs: CSRF-checked (`csrfOK`), admin-gated (`requireAdmin`), audited.

### 6. UI (templates)

- `admin_users.html`: create form gains a source toggle (Local / Directory);
  directory fields (username, email, display name, initial password) shown when
  Directory is selected and `s.directory != nil`.
- `admin_user_detail.html`: when the user is directory-backed **and** management
  is enabled, show Edit, Set-password, and Delete; otherwise keep today's
  read-only "managed by an external directory" note. Local users gain a Delete
  action behind the same guards.

## Error handling

- Directory write failures surface as a visible action error on the originating
  page (reuse `userActionError`); nothing is committed to the shadow on failure.
- Create is **directory-first**: Add must succeed before the shadow row is
  written. If the shadow write fails after a successful Add, surface the error
  and log loudly (next login would reconcile it anyway via `UpsertExternalUser`).
- Delete is **directory-first**: LDAP Delete must succeed before removing the
  shadow, so we never orphan a live directory entry's local state silently.

## Testing

- `internal/ldap`: unit tests for DN construction/escaping and request building.
  Integration tests against a containerized OpenLDAP if available; otherwise a
  fake `DirectoryManager` for handler tests.
- `internal/config`: preset/default resolution and `ManageEnabled` validation.
- `internal/store`: `DeleteUser` (row removed; `ErrNotFound` when absent).
- `internal/web`: handler tests with a fake `DirectoryManager` covering create,
  edit, set-password, delete, the admin/self/last-admin guards, and the
  management-disabled (read-only) path.

## Out of scope

AD write support, directory enable/disable write-back, local→LDAP promotion,
group/role management. Each is a follow-up with its own spec.
