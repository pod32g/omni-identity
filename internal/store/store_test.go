package store

import (
	"path/filepath"
	"testing"
)

func tempDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenRunsMigrations(t *testing.T) {
	db := tempDB(t)
	var name string
	err := db.sql.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='users'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("users table missing: %v", err)
	}
	if name != "users" {
		t.Errorf("got %q, want users", name)
	}
}

func TestAllTablesCreated(t *testing.T) {
	db := tempDB(t)
	want := []string{
		"users", "clients", "sessions", "authorization_codes",
		"refresh_tokens", "signing_keys", "schema_migrations",
	}
	for _, table := range want {
		var n int
		err := db.sql.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %q missing (n=%d, err=%v)", table, n, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = db.Close()

	// Reopening applies no new migrations and must not error.
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()

	v, err := currentVersion(db2.sql)
	if err != nil {
		t.Fatalf("currentVersion: %v", err)
	}
	if v < 1 {
		t.Errorf("schema version = %d, want >= 1", v)
	}
}

func TestForeignKeysEnabled(t *testing.T) {
	db := tempDB(t)
	var fk int
	if err := db.sql.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}
