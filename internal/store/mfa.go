package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

// ReplaceRecoveryCodes deletes any existing recovery codes for the user and
// inserts the supplied hashed codes in one transaction.
func (d *DB) ReplaceRecoveryCodes(ctx context.Context, userID string, codes []model.RecoveryCode) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used, created_at)
			VALUES (?, ?, ?, 0, ?)`,
			c.ID, userID, c.CodeHash, c.CreatedAt.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConsumeRecoveryCode atomically marks the matching unused code as used. It
// returns true if a code was consumed.
func (d *DB) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE mfa_recovery_codes SET used = 1
		WHERE user_id = ? AND code_hash = ? AND used = 0`,
		userID, codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CountRecoveryCodes returns the number of unused recovery codes for a user.
func (d *DB) CountRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE user_id = ? AND used = 0`, userID).Scan(&n)
	return n, err
}

// DeleteRecoveryCodes removes all recovery codes for a user (MFA disabled).
func (d *DB) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = ?`, userID)
	return err
}

// CreateLoginChallenge stores a pending second-factor challenge.
func (d *DB) CreateLoginChallenge(ctx context.Context, c *model.LoginChallenge) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO login_challenges (id, user_id, next, req, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Next, c.Req, c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	return err
}

// GetLoginChallenge fetches a non-expired challenge by id.
func (d *DB) GetLoginChallenge(ctx context.Context, id string) (*model.LoginChallenge, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, user_id, next, req, created_at, expires_at FROM login_challenges WHERE id = ?`, id)
	var c model.LoginChallenge
	err := row.Scan(&c.ID, &c.UserID, &c.Next, &c.Req, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &c, nil
}

// DeleteLoginChallenge removes a challenge (after success or abandonment).
func (d *DB) DeleteLoginChallenge(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM login_challenges WHERE id = ?`, id)
	return err
}
