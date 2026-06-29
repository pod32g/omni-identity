# SQLite → Postgres data migration

Date: 2026-06-29

## Goal

Move the live omni-identity deployment on host `192.168.68.34` (.34) from its
SQLite backend to the Postgres instance running on the same host, preserving
**all** existing data (every table).

## Context

Postgres support already exists in the codebase: the `store` package is
dual-dialect (`mattn/go-sqlite3` and `jackc/pgx/v5`), with a parallel
`migrations/postgres/` set that runs automatically on `OpenWith`. Queries use
`?` placeholders rebound to `$n` for Postgres by `conn.go`. What is missing is a
way to copy existing **rows** from a SQLite database into Postgres — `backup.go`
explicitly defers to "native Postgres tooling" for that.

The deployment runs as a distroless `omni-identity` container (binary at
`/omni-identity`) with SQLite on the named volume `omni-identity-data`
(`/data/omni-identity.db`). The `postgres` container is up on the same host,
port published on the LAN.

## Schema facts that drive the design

- 14 application tables (+ `schema_migrations`, which is **not** copied — the
  destination manages its own).
- Foreign keys: only `sessions`, `mfa_recovery_codes`, `login_challenges`,
  `password_tokens` reference `users(id)` (`ON DELETE CASCADE`). Everything else
  is independent. No self-referential or cyclic FKs.
- Dialect type differences that matter for a row copy:
  - SQLite stores booleans as `INTEGER 0/1`; Postgres columns are `BOOLEAN`.
  - SQLite `BLOB` (`branding.logo_blob`) ↔ Postgres `BYTEA`.
  - Timestamps: SQLite `TIMESTAMP` ↔ Postgres `TIMESTAMPTZ`.
  - `branding`, `settings` (and `app_secrets`) are single-row tables; the
    Postgres migrations seed default rows for `branding`/`settings`.

## Approach

Add a `migrate-data` subcommand that reuses the app's own dual-driver `store`
layer, so type conversions are handled by code that already knows these types
(rather than hand-tuned `pgloader` cast rules + a new host dependency).

### Component: `store.CopyData(ctx, src, dst *DB) (*CopyReport, error)`

- Guards: `dst` must be Postgres; `src` and `dst` must be at the **same**
  `schema_migrations` version (else abort — copying across schema versions is
  unsafe).
- Determines table order by introspecting the destination's foreign keys
  (`information_schema`) and topologically sorting (parents before children).
- In a single destination transaction:
  1. `DELETE FROM` each table in reverse dependency order (clears the seeded
     `branding`/`settings` default rows so source rows replace them).
  2. For each table in dependency order: read every row from `src`, coerce
     values to the destination column types (introspected per table — the only
     mandatory coercion is integer→`BOOLEAN`; `BYTEA`/timestamps/text pass
     through), and insert into `dst`.
- Returns a `CopyReport` with per-table source/destination row counts for
  verification. Source and destination counts must match per table.

### Component: `migrate-data` subcommand (`cmd/omni-identity`)

`omni-identity migrate-data --from-path <sqlite> --to-url <postgres>`

Opens the SQLite source (runs migrations: no-op on an up-to-date DB) and the
Postgres destination (runs migrations: creates the schema). Calls
`store.CopyData` and prints the per-table parity report. Mirrors the existing
`backup`/`integrity` subcommand convention.

## Execution on .34 (driven over SSH)

1. Build + test locally (integration test runs against an isolated scratch DB,
   never `appdb`).
2. On .34: take a consistent SQLite snapshot via the existing `omni-identity
   backup` (VACUUM INTO — WAL-safe, no downtime); keep it as the migration
   source and a backup.
3. `docker compose build` to get an image containing `migrate-data`.
4. Run a one-off container against the snapshot → Postgres; verify row-count
   parity.
5. Flip config: add `OMNI_DATABASE_DRIVER`/`OMNI_DATABASE_URL` to
   `docker-compose.yml` as `${...}` refs; the real URL (with password) goes in
   the host `.env`, never committed (matching how LDAP/logging secrets are
   handled). `docker compose up -d omni-identity` restarts on Postgres
   (seconds of downtime).
6. Validate `/healthz`, JWKS, and a test login.

## Rollback

The SQLite volume is left untouched. Reverting the two env vars and restarting
returns the service to SQLite instantly.

## Out of scope

- Removing SQLite support (kept as the local-dev default).
- Schema changes.
