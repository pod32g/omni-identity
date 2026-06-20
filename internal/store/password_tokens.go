package store

import (
	"context"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

// CreatePasswordToken stores a new activation/reset token (TokenHash must be set).
func (d *DB) CreatePasswordToken(ctx context.Context, t *model.PasswordToken) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO password_tokens (id, user_id, token_hash, purpose, used, expires_at, created_at)
		VALUES (?, ?, ?, ?, FALSE, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.Purpose, t.ExpiresAt.UTC(), t.CreatedAt.UTC())
	return err
}

// ConsumePasswordToken atomically marks the matching unused, unexpired token as
// used and returns it. ok is false when no such token exists (unknown, already
// used, or expired).
func (d *DB) ConsumePasswordToken(ctx context.Context, tokenHash string) (*model.PasswordToken, bool, error) {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE password_tokens SET used = TRUE
		WHERE token_hash = ? AND used = FALSE AND expires_at > ?`,
		tokenHash, time.Now().UTC())
	if err != nil {
		return nil, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if n == 0 {
		return nil, false, nil
	}
	row := d.sql.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, purpose, used, expires_at, created_at
		FROM password_tokens WHERE token_hash = ?`, tokenHash)
	var t model.PasswordToken
	if err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Purpose, &t.Used,
		&t.ExpiresAt, &t.CreatedAt); err != nil {
		return nil, false, err
	}
	return &t, true, nil
}

// GetValidPasswordToken returns the token row if it exists and is currently
// usable (unused, unexpired), else ErrNotFound.
func (d *DB) GetValidPasswordToken(ctx context.Context, tokenHash string) (*model.PasswordToken, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, purpose, used, expires_at, created_at
		FROM password_tokens WHERE token_hash = ? AND used = FALSE AND expires_at > ?`,
		tokenHash, time.Now().UTC())
	var t model.PasswordToken
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Purpose, &t.Used, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		return nil, ErrNotFound
	}
	return &t, nil
}

// DeletePasswordTokensForUser removes all of a user's tokens (after one is used,
// or when the account is reset).
func (d *DB) DeletePasswordTokensForUser(ctx context.Context, userID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM password_tokens WHERE user_id = ?`, userID)
	return err
}
