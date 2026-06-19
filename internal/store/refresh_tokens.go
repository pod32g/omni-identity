package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pod32g/omni-identity/internal/model"
)

const refreshColumns = `id, token_hash, client_id, user_id, scope, rotated_from, revoked, expires_at, created_at`

// CreateRefreshToken stores a new refresh token (TokenHash must be set).
func (d *DB) CreateRefreshToken(ctx context.Context, rt *model.RefreshToken) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO refresh_tokens (`+refreshColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rt.ID, rt.TokenHash, rt.ClientID, rt.UserID, rt.Scope, rt.RotatedFrom,
		rt.Revoked, rt.ExpiresAt.UTC(), rt.CreatedAt.UTC(),
	)
	return err
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
		&rt.RotatedFrom, &rt.Revoked, &rt.ExpiresAt, &rt.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}
