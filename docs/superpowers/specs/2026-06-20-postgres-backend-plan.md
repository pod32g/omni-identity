# Omni Identity — Pluggable Database Backend (SQLite + Postgres)

Date: 2026-06-20
Status: In progress

Goal: support an external Postgres database so multiple stateless Omni Identity
instances can share state (HA / horizontal scale), while keeping SQLite the
zero-config default. SQLite behavior and the single-binary story are unchanged.

## Approach

A thin **dialect/rebind wrapper** around `database/sql`, not a rewrite of the
~60 query call sites:

- `internal/store/conn.go`: a `dbConn` wrapping `*sql.DB` and a `txConn`
  wrapping `*sql.Tx`. Both shadow `ExecContext`/`QueryContext`/`QueryRowContext`
  to **rebind `?` → `$N`** when the dialect is Postgres (no-op for SQLite).
  `BeginTx` returns a `*txConn`. Existing call sites (`d.sql.ExecContext(...)`,
  `tx.ExecContext(...)`) are unchanged — they transparently rebind.
- The DB's queries use only `?` placeholders today (verified: 178 `?`, 0 `$N`),
  and never contain a literal `?` in string data, so a naive sequential rebind
  (the sqlx approach) is correct.

## Driver

`github.com/jackc/pgx/v5/stdlib` (pure Go; no CGO for the Postgres path). SQLite
remains `mattn/go-sqlite3` (CGO).

## Dialect-specific handling (small, enumerated)

- **Migrations**: split into `migrations/sqlite/` and `migrations/postgres/`.
  The runner selects by dialect, splits each file into statements (avoids the
  pgx multi-statement-Exec limitation), and rebinds the one parameterized
  bookkeeping insert. Postgres translations: `BLOB`→`BYTEA`, boolean columns
  `INTEGER…`→`BOOLEAN…`, `TIMESTAMP`→`TIMESTAMPTZ`; `INSERT OR IGNORE`→
  `ON CONFLICT DO NOTHING` lives in Go, not migrations.
- **`app_secret.go` upsert**: `INSERT OR IGNORE` (SQLite) vs
  `INSERT … ON CONFLICT (id) DO NOTHING` (Postgres), branched on dialect.
- **`backup.go`** (`VACUUM INTO`, `PRAGMA integrity_check`): SQLite-only; returns
  a clear "use pg_dump" error on Postgres. These back the `backup`/`integrity`
  CLI subcommands, which remain SQLite operations.
- **Connection pool**: SQLite keeps `SetMaxOpenConns(1)` (single writer);
  Postgres uses a real pool.

## Concurrency correctness on Postgres

SQLite's single-writer made some read-modify-write paths implicitly safe. On a
real pool they must be atomic on their own:

- `RotateRefreshToken`: already a conditional `UPDATE … WHERE revoked = 0` with
  a row-count check — atomic on both. No change.
- `RecordFailedLogin`: change the read-then-write to a single atomic
  `UPDATE … SET failed_login_count = failed_login_count + 1, locked_until =
  CASE …` then read the new count back. Portable and race-free on both backends.

## Config

`database.driver` (`sqlite` default | `postgres`), `database.path` (sqlite),
`database.url` (postgres DSN). Env: `OMNI_DATABASE_DRIVER`, `OMNI_DATABASE_URL`.
`store.Open(path)` stays (SQLite, used by tests/CLI); new `store.OpenWith(driver,
dsn)` dispatches.

## Testing

- Unchanged: the full existing suite runs on SQLite (regression gate).
- New: `rebind` unit tests (pure, no DB).
- New: env-gated Postgres integration test (`OMNI_TEST_POSTGRES_URL`) exercising
  migrations + representative CRUD/transaction paths; skips with a message when
  unset. `make test-postgres` and a documented `docker run` one-liner.

## Out of scope

MySQL or other engines; read-replica routing; automatic SQLite→Postgres data
migration.
