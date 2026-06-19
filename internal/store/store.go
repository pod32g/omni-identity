// Package store provides persistence for Omni Identity. The concrete
// implementation is SQLite (CGO, mattn/go-sqlite3); a single DB type fronts all
// repositories so a different backend could be substituted later.
package store

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// DB is the SQLite-backed store. It embeds the *sql.DB handle and exposes
// repository methods (added per milestone).
type DB struct {
	sql *sql.DB
}

// Open opens the SQLite database at path, enables sane pragmas, runs pending
// migrations, and returns a ready store.
func Open(path string) (*DB, error) {
	dsn := fmt.Sprintf(
		"%s?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL",
		path,
	)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite allows a single writer; serialize to avoid "database is locked".
	sqlDB.SetMaxOpenConns(1)

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := migrate(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{sql: sqlDB}, nil
}

// Ping verifies the database connection is alive.
func (d *DB) Ping() error { return d.sql.Ping() }

// Close releases the database handle.
func (d *DB) Close() error { return d.sql.Close() }
