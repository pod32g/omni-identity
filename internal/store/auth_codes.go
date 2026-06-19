package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const authCodeColumns = `code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, used, created_at, auth_time`

// CreateAuthCode stores a new authorization code (CodeHash must be set).
func (d *DB) CreateAuthCode(ctx context.Context, c *model.AuthorizationCode) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO authorization_codes (`+authCodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce,
		c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt.UTC(), c.Used,
		c.CreatedAt.UTC(), c.AuthTime.UTC(),
	)
	return err
}

// ConsumeAuthCode atomically fetches an unused, unexpired code and marks it
// used. Missing, used, or expired codes return ErrNotFound.
func (d *DB) ConsumeAuthCode(ctx context.Context, codeHash string) (*model.AuthorizationCode, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`SELECT `+authCodeColumns+` FROM authorization_codes WHERE code_hash = ?`, codeHash)
	c, err := scanAuthCode(row)
	if err != nil {
		return nil, err
	}
	if c.Used || time.Now().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code_hash = ?`, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	c.Used = true
	return c, nil
}

// DeleteExpiredAuthCodes removes codes that expired before now.
func (d *DB) DeleteExpiredAuthCodes(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM authorization_codes WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanAuthCode(s scanner) (*model.AuthorizationCode, error) {
	var c model.AuthorizationCode
	err := s.Scan(
		&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
		&c.CodeChallenge, &c.CodeChallengeMethod, &c.ExpiresAt, &c.Used,
		&c.CreatedAt, &c.AuthTime,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
