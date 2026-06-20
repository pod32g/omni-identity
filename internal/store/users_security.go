package store

import (
	"context"
	"time"
)

// RecordFailedLogin atomically increments the failed-login counter and, when it
// reaches threshold, locks the account until lockUntil. It returns the new
// count. The increment and conditional lock are a single UPDATE so the path is
// race-free on a real connection pool (Postgres), not just under SQLite's
// single writer.
func (d *DB) RecordFailedLogin(ctx context.Context, id string, threshold int, lockUntil time.Time) (int, error) {
	if _, err := d.sql.ExecContext(ctx, `
		UPDATE users
		SET failed_login_count = failed_login_count + 1,
		    locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END,
		    updated_at = ?
		WHERE id = ?`,
		threshold, lockUntil.UTC(), time.Now().UTC(), id); err != nil {
		return 0, err
	}
	var count int
	if err := d.sql.QueryRowContext(ctx,
		`SELECT failed_login_count FROM users WHERE id = ?`, id).Scan(&count); err != nil {
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
