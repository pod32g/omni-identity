# LDAP Authentication Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users sign in on the existing hosted login page with LDAP / Active Directory credentials, verified via a standards-based, pluggable authentication **connector**; Omni JIT-provisions a local mirror user, applies optional TOTP MFA, and issues OIDC tokens as usual.

**Architecture:** A leaf `internal/authn` package defines a Dex-style `PasswordConnector` interface + `Identity`. `internal/ldap` implements it with `go-ldap/ldap/v3` search-then-bind, schema **presets** (AD / OpenLDAP), and conformance hardening (paged search, size/time limits, escaped filters). The `web` login handler holds `[]authn.PasswordConnector`: local users keep the existing hardened path; otherwise connectors are consulted, the winner is upserted (`auth_source='ldap'`), and flows through the *unchanged* post-auth tail (MFA → session → OIDC). Config is YAML+env, off by default. Outbound LDAP server is out of scope.

**Tech Stack:** Go, `github.com/go-ldap/ldap/v3`, SQLite + Postgres, existing `net/http`/`database/sql` stack.

---

## File structure

- `internal/authn/authn.go` — `Identity`, `PasswordConnector` interface (leaf pkg). (create)
- `internal/config/config.go` — `LDAPConfig` + preset resolution + env + validation. (modify)
- `internal/model/model.go` — `User.AuthSource`, `User.ExternalID`, `User.IsLocal()`. (modify)
- `internal/store/migrations/{sqlite,postgres}/0007_ldap.sql` — schema. (create)
- `internal/store/users.go` — columns/scan/insert; `GetUserByExternalID`, `UpsertExternalUser`. (modify)
- `internal/ldap/ldap.go` (+ `presets.go`) — connector impl. (create)
- `internal/ldap/ldap_test.go` — pure tests + gated integration. (create)
- `internal/web/server.go` — `connectors []authn.PasswordConnector`, wiring. (modify)
- `internal/web/auth_handlers.go` — source-aware credential check. (modify)
- `internal/web/auth_ldap_test.go` — login-flow tests with a fake connector. (create)
- `internal/web/{forgot_handler,password_reset_handler,account_handler,admin_security}.go` — guard local flows. (modify)
- `README.md`, `config.example.yaml`, `.env.example` — docs. (modify)

---

### Task 1: `internal/authn` connector contract

**Files:** Create `internal/authn/authn.go`, `internal/authn/authn_test.go`

- [ ] **Step 1: Test** — assert the interface is satisfiable by a tiny fake and `Identity` carries the expected fields (compile-level contract test).

```go
package authn

import (
	"context"
	"testing"
)

type stubConn struct{}

func (stubConn) ID() string { return "stub" }
func (stubConn) Login(context.Context, string, string) (Identity, bool, error) {
	return Identity{Connector: "stub", Username: "x"}, true, nil
}

func TestPasswordConnectorContract(t *testing.T) {
	var c PasswordConnector = stubConn{}
	id, ok, err := c.Login(context.Background(), "x", "y")
	if err != nil || !ok || id.Connector != "stub" {
		t.Fatalf("bad contract: %+v ok=%v err=%v", id, ok, err)
	}
}
```

- [ ] **Step 2:** Run `go test ./internal/authn/` → FAIL (package missing).
- [ ] **Step 3: Implement** `authn.go` exactly as in spec §2 (`Identity` struct with `Connector, ExternalID, Username, Email, DisplayName string; IsAdmin bool`; `PasswordConnector` with `ID() string` and `Login(ctx, username, password) (Identity, bool, error)`).
- [ ] **Step 4:** Run `go test ./internal/authn/` → PASS.
- [ ] **Step 5:** Commit: `feat(authn): pluggable password-connector contract`.

---

### Task 2: LDAP config with presets

**Files:** Modify `internal/config/config.go`; Test `internal/config/config_test.go`

- [ ] **Step 1: Tests** — disabled-by-default; enabled requires `url`+`base_dn`; **preset fills filter/attrs** and explicit fields override; env override (`OMNI_LDAP_*`). Read `config_test.go` first and reuse its load helper.

```go
func TestLDAPPresetActiveDirectory(t *testing.T) {
	yaml := "server:\n  public_url: https://id.example\n" +
		"ldap:\n  enabled: true\n  preset: activedirectory\n" +
		"  url: ldaps://dc:636\n  base_dn: dc=x\n"
	cfg := mustLoad(t, yaml) // reuse existing helper
	if cfg.LDAP.UserFilter != "(&(objectClass=user)(sAMAccountName=%s))" ||
		cfg.LDAP.AttrUsername != "sAMAccountName" {
		t.Fatalf("AD preset not applied: %+v", cfg.LDAP)
	}
}

func TestLDAPExplicitFilterOverridesPreset(t *testing.T) {
	yaml := "server:\n  public_url: https://id.example\n" +
		"ldap:\n  enabled: true\n  preset: openldap\n  url: ldap://h\n" +
		"  base_dn: dc=x\n  user_filter: \"(cn=%s)\"\n"
	cfg := mustLoad(t, yaml)
	if cfg.LDAP.UserFilter != "(cn=%s)" {
		t.Fatalf("explicit filter should win: %q", cfg.LDAP.UserFilter)
	}
}

func TestLDAPDisabledByDefault(t *testing.T) {
	cfg := mustLoad(t, "server:\n  public_url: https://id.example\n")
	if cfg.LDAP.Enabled {
		t.Fatal("LDAP should be off by default")
	}
}

func TestLDAPEnabledRequiresURL(t *testing.T) {
	yaml := "server:\n  public_url: https://id.example\n" +
		"ldap:\n  enabled: true\n  preset: openldap\n  base_dn: dc=x\n"
	if _, err := loadErr(t, yaml); err == nil { // helper that returns the error
		t.Fatal("missing ldap.url must error")
	}
}
```

- [ ] **Step 2:** Run `go test ./internal/config/ -run TestLDAP` → FAIL.
- [ ] **Step 3: Implement.** Add `LDAP LDAPConfig` to `Config`. `LDAPConfig` fields: `Enabled bool; Preset, URL string; StartTLS bool; BindDN, BindPassword, BaseDN, UserFilter, AttrUsername, AttrEmail, AttrDisplayName, AdminGroupDN, GroupFilter, CACertFile string; InsecureSkipVerify bool; Timeout time.Duration`. Add the matching `fileConfig.LDAP` yaml block (Timeout as string). In `Load`, **after** copying raw fields, call `applyLDAPPreset(&cfg.LDAP)` which sets defaults from the preset table (spec §3.2) only where the field is empty; default preset `openldap`; parse `Timeout` via `parseDurationOr(..., 10*time.Second)`. Validation when `Enabled`: require `URL`, `BaseDN`, and `strings.Contains(UserFilter, "%s")`. Add all `OMNI_LDAP_*` env overrides (`ENABLED, PRESET, URL, START_TLS, BIND_DN, BIND_PASSWORD, BASE_DN, USER_FILTER, ATTR_USERNAME, ATTR_EMAIL, ATTR_DISPLAY_NAME, ADMIN_GROUP_DN, GROUP_FILTER, CA_CERT_FILE, INSECURE_SKIP_VERIFY, TIMEOUT`). Add `"strings"` import.

`applyLDAPPreset` sketch:

```go
func applyLDAPPreset(c *LDAPConfig) {
	p := c.Preset
	if p == "" {
		p = "openldap"
	}
	def := map[string]map[string]string{
		"openldap": {"uf": "(&(objectClass=inetOrgPerson)(uid=%s))", "u": "uid", "e": "mail", "d": "cn", "gf": "(&(objectClass=groupOfNames)(member=%s))"},
		"activedirectory": {"uf": "(&(objectClass=user)(sAMAccountName=%s))", "u": "sAMAccountName", "e": "mail", "d": "displayName", "gf": "(&(objectClass=group)(member=%s))"},
	}[p]
	if def == nil {
		def = map[string]string{"uf": "(&(objectClass=inetOrgPerson)(uid=%s))", "u": "uid", "e": "mail", "d": "cn", "gf": "(&(objectClass=groupOfNames)(member=%s))"}
	}
	c.UserFilter = orDefault(c.UserFilter, def["uf"])
	c.AttrUsername = orDefault(c.AttrUsername, def["u"])
	c.AttrEmail = orDefault(c.AttrEmail, def["e"])
	c.AttrDisplayName = orDefault(c.AttrDisplayName, def["d"])
	c.GroupFilter = orDefault(c.GroupFilter, def["gf"])
}
```

- [ ] **Step 4:** Run `go test ./internal/config/ -run TestLDAP` → PASS.
- [ ] **Step 5:** Commit: `feat(config): LDAP backend config with AD/OpenLDAP presets`.

---

### Task 3: User model + store

**Files:** Modify `internal/model/model.go`, `internal/store/users.go`; create both `0007_ldap.sql`; Test `internal/store/users_test.go`

- [ ] **Step 1: Test** `UpsertExternalUser` inserts a passwordless `auth_source='ldap'` row, then updates (email + promote admin) the same id; and refuses to shadow a local user of the same username. (Reuse the file's test-DB helper.)

```go
func TestUpsertExternalUserInsertThenUpdate(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	u, err := db.UpsertExternalUser(ctx, "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil { t.Fatal(err) }
	if u.AuthSource != "ldap" || u.PasswordHash != "" || u.ID == "" { t.Fatalf("bad insert %+v", u) }
	u2, err := db.UpsertExternalUser(ctx, "ldap", "uid=jane,dc=x", "jane", "j2@x", "Jane D", true)
	if err != nil { t.Fatal(err) }
	if u2.ID != u.ID || !u2.IsAdmin || u2.Email != "j2@x" { t.Fatalf("bad update %+v", u2) }
}

func TestUpsertExternalUserRefusesLocalCollision(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	_ = db.CreateUser(ctx, &model.User{ID: "1", Username: "bob", Email: "b@x", PasswordHash: "h", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if _, err := db.UpsertExternalUser(ctx, "ldap", "uid=bob,dc=x", "bob", "b@y", "Bob", false); err == nil {
		t.Fatal("must refuse to shadow a local account")
	}
}
```

- [ ] **Step 2:** Run `go test ./internal/store/ -run TestUpsertExternalUser` → FAIL.
- [ ] **Step 3: Implement** model fields + `IsLocal()` (spec §4.2); both migrations (cols + partial unique index `idx_users_external` on `(auth_source, external_id) WHERE external_id <> ''`); extend `userColumns`, `CreateUser` (14 placeholders, default blank `AuthSource`→`"local"`), `scanUser`; add `GetUserByExternalID` and `UpsertExternalUser(ctx, source, externalID, username, email, displayName string, isAdmin bool) (*model.User, error)`. Add `"fmt"` + `uuid` imports to `users.go`.
- [ ] **Step 4:** Run `go test ./internal/store/` → PASS.
- [ ] **Step 5:** Commit: `feat(store): auth_source/external_id + external-user upsert`.

---

### Task 4: LDAP connector

**Files:** Create `internal/ldap/ldap.go`, `internal/ldap/presets.go` (optional split), `internal/ldap/ldap_test.go`; modify `go.mod`/`go.sum`

- [ ] **Step 1:** `go get github.com/go-ldap/ldap/v3@latest`.
- [ ] **Step 2: Pure tests** — `renderFilter` escapes via `EscapeFilter`; `New` rejects empty URL/base/filter; `Login` rejects empty password with `ok=false,err=nil`; `ID()=="ldap"`. (See spec §3.1/§3.3.)
- [ ] **Step 3:** Run `go test ./internal/ldap/` → FAIL.
- [ ] **Step 4: Implement** `Client` satisfying `authn.PasswordConnector`:
  - `New(cfg Config) (*Client, error)` builds a `*tls.Config` (ServerName from URL host, optional CA file, `InsecureSkipVerify`).
  - `ID() string { return "ldap" }`.
  - `Login(ctx, username, password)`: empty-check → dial → service/anon bind → **paged** subtree search (`SearchWithPaging`, page 1000, `SizeLimit`/`TimeLimit` from timeout, `NeverDerefAliases`) with `renderFilter(user_filter, username)` → exactly one entry else `ok=false` → fresh-conn bind as entry DN with password (`LDAPResultInvalidCredentials`→`ok=false`; other→`err`) → `isAdmin` (base-scoped group search, fail-closed) → return `authn.Identity{Connector:"ldap", ExternalID: entry.DN, ...}, true, nil`.
  - `renderFilter(tmpl, v) = strings.Replace(tmpl, "%s", goldap.EscapeFilter(v), 1)`.
  - Config struct mirrors `config.LDAPConfig` (sans Enabled/Preset — already resolved).
- [ ] **Step 5:** Run `go test ./internal/ldap/` → PASS (pure tests). Add gated `TestLoginIntegration` (skips unless `OMNI_TEST_LDAP_URL`).
- [ ] **Step 6:** Commit: `feat(ldap): standards-based LDAP password connector with presets`.

---

### Task 5: Source-aware login flow

**Files:** Modify `internal/web/server.go`, `internal/web/auth_handlers.go`; create `internal/web/auth_ldap_test.go`

- [ ] **Step 1: Tests** with a fake connector: (a) unknown-local user authenticates via connector → 303 redirect + a provisioned `auth_source='ldap'`, admin-mapped user exists; (b) existing local user still logs in even when the connector would reject. Reuse the package's `newTestServer`/login helpers (read `auth_handlers_test.go`).

```go
type fakeConn struct{ id authn.Identity; ok bool; err error }
func (f fakeConn) ID() string { return "ldap" }
func (f fakeConn) Login(context.Context, string, string) (authn.Identity, bool, error) { return f.id, f.ok, f.err }
```

- [ ] **Step 2:** Run `go test ./internal/web/ -run TestLoginVia` → FAIL.
- [ ] **Step 3: Implement.** Add `connectors []authn.PasswordConnector` to `Server`; in `NewServer`, when `cfg.LDAP.Enabled`, build `ldap.New(...)` and append. Refactor the credential block in `handleLoginSubmit` into the switch from spec §5: local-and-`IsLocal()` → existing path; else loop `connectors` (first `ok` wins → `UpsertExternalUser`, disabled-check); else `DummyVerify`+invalid. Connector `err` → `slog.Error` + generic invalid + audit. Keep the shared tail (MFA/session/audit/OIDC) untouched. Imports: `errors`, `log/slog`, `internal/authn`, `internal/ldap`.
- [ ] **Step 4:** Run `go build ./... && go test ./internal/web/ -run TestLogin` → PASS, then `go test ./...` → PASS.
- [ ] **Step 5:** Commit: `feat(web): authenticate via pluggable connectors (LDAP) with JIT provisioning`.

---

### Task 6: Guard local-password flows for directory users

**Files:** Modify `internal/web/forgot_handler.go`, `password_reset_handler.go`, `account_handler.go`, `admin_security.go`; extend `auth_ldap_test.go`

- [ ] **Step 1: Tests** — `/forgot` for an LDAP user issues **no** reset token (generic response preserved); `/account/password` for an LDAP user is refused (not 303). Reuse existing helpers; query the store for token count.
- [ ] **Step 2:** Run the new tests → FAIL.
- [ ] **Step 3: Implement** guards (read each handler first; match its var names): `/forgot` skip token issuance when `!user.IsLocal()` but render the same generic "sent" page; `/account/password` early `403` when `!user.IsLocal()`; admin reset-link `400` when `!target.IsLocal()`; defensive `!user.IsLocal()` reject in `/set-password`.
- [ ] **Step 4:** Run `go test ./internal/web/ -run 'TestForgot|TestAccountPassword|TestSetPassword'` → PASS.
- [ ] **Step 5:** Commit: `feat(web): block local password flows for directory-managed users`.

---

### Task 7: Admin UI surface

**Files:** Modify the users template/handler + `internal/web/admin_settings.go` (+ settings template)

- [ ] **Step 1:** Users list: render auth source (Local/LDAP); hide per-user password/reset-link actions when `!u.IsLocal()`.
- [ ] **Step 2:** Settings: pass a read-only LDAP view-model from `s.cfg.LDAP` (Enabled, URL, BaseDN, AdminGroupDN — never the bind password) and render a "Directory (LDAP)" panel mirroring SMTP status.
- [ ] **Step 3:** `go build ./... && go test ./internal/web/` → PASS. Commit: `feat(admin): show auth source and read-only LDAP status`.

---

### Task 8: Docs

**Files:** Modify `config.example.yaml`, `.env.example`, `README.md`

- [ ] **Step 1:** `config.example.yaml`: commented `ldap:` block (all fields incl. `preset`), note bind password is a config/env-only secret.
- [ ] **Step 2:** `.env.example`: commented `OMNI_LDAP_*` vars.
- [ ] **Step 3:** `README.md`: add LDAP to features + a "Directory / LDAP" section (search-then-bind, presets, JIT provisioning, TOTP still applies, admin via group, local-password flows disabled for directory users).
- [ ] **Step 4:** Commit: `docs: document the LDAP authentication backend`.

---

## Self-review notes

- **Spec coverage:** authn contract (T1), config+presets (T2), model/store/migration (T3), connector + conformance (T4), source-aware login + JIT + MFA-via-tail (T5), local-flow guards (T6), admin UI (T7), docs (T8). Outbound server intentionally excluded (spec §6).
- **No import cycle:** `store.UpsertExternalUser` takes flat params; `internal/authn` is a leaf; `ldap` imports `authn`; `web` imports both.
- **Type consistency:** `authn.Identity{Connector,ExternalID,Username,Email,DisplayName,IsAdmin}` is produced in T4, consumed in T5; `UpsertExternalUser(source, externalID, username, email, displayName, isAdmin)` order is identical everywhere; `LDAPConfig.Enabled` is a **field** (read `cfg.LDAP.Enabled`, no method).
- **Presets** resolved in `config.Load` so the connector receives concrete filters; explicit fields always override.
