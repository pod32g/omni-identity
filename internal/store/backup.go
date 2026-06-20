package store

import (
	"context"
	"fmt"
	"strings"
)

// errSQLiteOnly is returned by the SQLite-specific maintenance helpers when the
// store is backed by Postgres (use pg_dump / standard Postgres tooling instead).
var errSQLiteOnly = fmt.Errorf("operation is only supported on the SQLite backend; use native Postgres tooling (pg_dump, etc.)")

// BackupTo writes a consistent online snapshot of the database to out using
// SQLite's VACUUM INTO (WAL-safe; does not block the live writer). out must not
// already exist. Used by the deploy pipeline to back up before a release.
func (d *DB) BackupTo(ctx context.Context, out string) error {
	if d.dialect != dialectSQLite {
		return errSQLiteOnly
	}
	// VACUUM INTO does not accept bound parameters, so quote the path safely.
	quoted := "'" + strings.ReplaceAll(out, "'", "''") + "'"
	if _, err := d.sql.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return fmt.Errorf("backup to %s: %w", out, err)
	}
	return nil
}

// IntegrityCheck runs PRAGMA integrity_check. It returns ok=true when the
// database reports "ok"; otherwise the reported problems are returned.
func (d *DB) IntegrityCheck(ctx context.Context) (bool, []string, error) {
	if d.dialect != dialectSQLite {
		return false, nil, errSQLiteOnly
	}
	rows, err := d.sql.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()

	var problems []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return false, nil, err
		}
		problems = append(problems, s)
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}
	if len(problems) == 1 && problems[0] == "ok" {
		return true, nil, nil
	}
	return false, problems, nil
}
