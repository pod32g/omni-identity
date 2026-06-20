package store

import (
	"context"
	"time"
)

// RecordFailedLogin increments the failed-login counter and, when it reaches
// threshold, locks the account until lockUntil. Returns the new count.
func (d *DB) RecordFailedLogin(ctx context.Context, id string, threshold int, lockUntil time.Time) (int, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT failed_login_count FROM users WHERE id = ?`, id).Scan(&count); err != nil {
		return 0, err
	}
	count++

	var locked any
	if count >= threshold {
		locked = lockUntil.UTC()
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?`,
		count, locked, time.Now().UTC(), id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// ResetFailedLogins clears the failed-login counter and any lock (after a
// successful login or an admin unlock).
func (d *DB) ResetFailedLogins(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
		time.Now().UTC(), id)
	return err
}

// SetUserMFA enables or disables MFA, storing (or clearing) the encrypted TOTP
// secret. When disabling, recovery codes should be cleared by the caller.
func (d *DB) SetUserMFA(ctx context.Context, id string, enabled bool, encSecret string) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE users SET mfa_enabled = ?, totp_secret = ?, updated_at = ? WHERE id = ?`,
		enabled, encSecret, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	return requireRow(res)
}
