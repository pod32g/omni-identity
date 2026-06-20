// Package store provides persistence for Omni Identity. It supports two
// backends behind one DB type: SQLite (CGO, mattn/go-sqlite3) for the
// zero-config single-binary default, and Postgres (pure-Go pgx) for
// multi-instance / high-availability deployments. Queries are written once with
// `?` placeholders and rebound per dialect by the connection wrapper.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "github.com/mattn/go-sqlite3"    // registers the "sqlite3" driver
)

// Driver names accepted by OpenWith.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// DB is the backing store. It fronts all repositories and rebinds queries for
// the active SQL dialect.
type DB struct {
	sql     *dbConn
	dialect dialect
}

// Open opens a SQLite database at path (the default backend). It remains for
// the CLI subcommands and tests; the server uses OpenWith.
func Open(path string) (*DB, error) {
	return OpenWith(DriverSQLite, path)
}

// OpenWith opens the store for the given driver. For "sqlite" (or ""), dsn is a
// file path; for "postgres", dsn is a connection URL. Pending migrations are
// applied before the store is returned.
func OpenWith(driver, dsn string) (*DB, error) {
	switch driver {
	case "", DriverSQLite:
		return openSQLite(dsn)
	case DriverPostgres:
		return openPostgres(dsn)
	default:
		return nil, fmt.Errorf("unknown database driver %q (want %q or %q)", driver, DriverSQLite, DriverPostgres)
	}
}

func openSQLite(path string) (*DB, error) {
	dsn := fmt.Sprintf("%s?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL", path)
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite allows a single writer; serialize to avoid "database is locked".
	sqlDB.SetMaxOpenConns(1)
	return finishOpen(sqlDB, dialectSQLite)
}

func openPostgres(url string) (*DB, error) {
	if url == "" {
		return nil, fmt.Errorf("postgres: database url is required")
	}
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// A real connection pool (unlike SQLite's single writer).
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return finishOpen(sqlDB, dialectPostgres)
}

func finishOpen(sqlDB *sql.DB, d dialect) (*DB, error) {
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping %s: %w", d, err)
	}
	if err := migrate(sqlDB, d); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{sql: &dbConn{DB: sqlDB, dialect: d}, dialect: d}, nil
}

// Ping verifies the database connection is alive.
func (d *DB) Ping() error { return d.sql.Ping() }

// Close releases the database handle.
func (d *DB) Close() error { return d.sql.Close() }
