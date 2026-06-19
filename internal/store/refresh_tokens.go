package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pod32g/omni-identity/internal/model"
)

const refreshColumns = `id, token_hash, client_id, user_id, scope, rotated_from, revoked, expires_at, created_at, auth_time`

// CreateRefreshToken stores a new refresh token (TokenHash must be set).
func (d *DB) CreateRefreshToken(ctx context.Context, rt *model.RefreshToken) error {
	_, err := d.sql.ExecContext(ctx, insertRefreshSQL,
		rt.ID, rt.TokenHash, rt.ClientID, rt.UserID, rt.Scope, rt.RotatedFrom,
		rt.Revoked, rt.ExpiresAt.UTC(), rt.CreatedAt.UTC(), rt.AuthTime.UTC(),
	)
	return err
}

const insertRefreshSQL = `
	INSERT INTO refresh_tokens (` + refreshColumns + `)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// RotateRefreshToken atomically revokes the presented token (only if currently
// active) and, when newRT is non-nil, inserts the replacement in the same
// transaction. It returns ok=false if the token was already revoked (lost the
// rotation race / reuse), in which case nothing is changed. This makes refresh
// rotation safe against concurrent double-spend and never leaves a broken chain
// if the replacement insert fails.
func (d *DB) RotateRefreshToken(ctx context.Context, oldID string, newRT *model.RefreshToken) (bool, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0`, oldID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil // already revoked elsewhere
	}

	if newRT != nil {
		if _, err := tx.ExecContext(ctx, insertRefreshSQL,
			newRT.ID, newRT.TokenHash, newRT.ClientID, newRT.UserID, newRT.Scope,
			newRT.RotatedFrom, newRT.Revoked, newRT.ExpiresAt.UTC(),
			newRT.CreatedAt.UTC(), newRT.AuthTime.UTC(),
		); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// GetRefreshTokenByHash fetches a refresh token by its hash. It returns the row
// even if revoked or expired so callers can implement reuse detection.
func (d *DB) GetRefreshTokenByHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token_hash = ?`, hash)
	return scanRefreshToken(row)
}

// RevokeRefreshToken marks a single refresh token revoked.
func (d *DB) RevokeRefreshToken(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, id)
	return err
}

// RevokeRefreshTokensForUserClient revokes every refresh token for a given
// user+client pair (used for reuse detection and logout-all).
func (d *DB) RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND client_id = ?`,
		userID, clientID)
	return err
}

func scanRefreshToken(s scanner) (*model.RefreshToken, error) {
	var rt model.RefreshToken
	err := s.Scan(
		&rt.ID, &rt.TokenHash, &rt.ClientID, &rt.UserID, &rt.Scope,
		&rt.RotatedFrom, &rt.Revoked, &rt.ExpiresAt, &rt.CreatedAt, &rt.AuthTime,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}
