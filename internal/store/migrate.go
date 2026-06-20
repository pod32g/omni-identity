package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
}

// migrate creates the schema_migrations bookkeeping table and applies every
// embedded migration (for the active dialect) whose version is greater than the
// current schema version, each in its own transaction. It is idempotent.
func migrate(db *sql.DB, d dialect) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	current, err := currentVersion(db)
	if err != nil {
		return err
	}

	migs, err := loadMigrations(d)
	if err != nil {
		return err
	}

	dir := "migrations/" + d.String()
	for _, m := range migs {
		if m.version <= current {
			continue
		}
		body, err := migrationFS.ReadFile(dir + "/" + m.name)
		if err != nil {
			return fmt.Errorf("read %s: %w", m.name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		// Execute statement-by-statement: the pgx driver rejects multiple
		// commands in a single Exec, and splitting works for SQLite too.
		for _, stmt := range splitStatements(string(body)) {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply %s: %w", m.name, err)
			}
		}
		if _, err := tx.Exec(rebind(d, `INSERT INTO schema_migrations(version) VALUES(?)`), m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", m.name, err)
		}
	}
	return nil
}

// splitStatements breaks a migration file into individual SQL statements,
// stripping `--` line comments. The store's migrations contain no semicolons
// inside string literals or procedural blocks, so a simple split is correct.
func splitStatements(body string) []string {
	var noComments strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		noComments.WriteString(line)
		noComments.WriteByte('\n')
	}
	var out []string
	for _, raw := range strings.Split(noComments.String(), ";") {
		if s := strings.TrimSpace(raw); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func loadMigrations(d dialect) ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations/" + d.String())
	if err != nil {
		return nil, err
	}
	var migs []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		verStr := strings.SplitN(e.Name(), "_", 2)[0]
		v, err := strconv.Atoi(verStr)
		if err != nil {
			return nil, fmt.Errorf("bad migration filename %q: %w", e.Name(), err)
		}
		migs = append(migs, migration{version: v, name: e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}

func currentVersion(db *sql.DB) (int, error) {
	var v sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}
