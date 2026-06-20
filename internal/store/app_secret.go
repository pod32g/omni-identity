package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GetOrCreateAppSecret returns the persisted base64 server secret, generating
// and storing one (via gen) on first use. The write is idempotent under the
// single-writer SQLite configuration.
func (d *DB) GetOrCreateAppSecret(ctx context.Context, gen func() (string, error)) (string, error) {
	var key string
	err := d.sql.QueryRowContext(ctx, `SELECT key_b64 FROM app_secrets WHERE id = 1`).Scan(&key)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	key, err = gen()
	if err != nil {
		return "", err
	}
	if _, err := d.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_secrets (id, key_b64, created_at) VALUES (1, ?, ?)`,
		key, time.Now().UTC()); err != nil {
		return "", err
	}
	// Re-read in case a concurrent caller won the insert race.
	if err := d.sql.QueryRowContext(ctx, `SELECT key_b64 FROM app_secrets WHERE id = 1`).Scan(&key); err != nil {
		return "", err
	}
	return key, nil
}
