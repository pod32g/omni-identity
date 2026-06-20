package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const authRequestColumns = `id, client_id, redirect_uri, response_type, scope, state, nonce, ` +
	`code_challenge, code_challenge_method, created_at, expires_at`

// CreateAuthRequest stores a pending authorization request.
func (d *DB) CreateAuthRequest(ctx context.Context, a *model.AuthRequest) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO auth_requests (`+authRequestColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ClientID, a.RedirectURI, a.ResponseType, a.Scope, a.State,
		a.Nonce, a.CodeChallenge, a.CodeChallengeMethod,
		a.CreatedAt.UTC(), a.ExpiresAt.UTC(),
	)
	return err
}

// GetAuthRequest fetches a pending request by id. Expired rows return
// ErrNotFound so callers treat them uniformly as missing/expired.
func (d *DB) GetAuthRequest(ctx context.Context, id string) (*model.AuthRequest, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+authRequestColumns+` FROM auth_requests WHERE id = ?`, id)

	var a model.AuthRequest
	err := row.Scan(&a.ID, &a.ClientID, &a.RedirectURI, &a.ResponseType, &a.Scope,
		&a.State, &a.Nonce, &a.CodeChallenge, &a.CodeChallengeMethod,
		&a.CreatedAt, &a.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Now().UTC().After(a.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &a, nil
}

// DeleteAuthRequest removes a pending request (single-use after a code issues).
func (d *DB) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

// DeleteExpiredAuthRequests purges expired rows; returns the number removed.
func (d *DB) DeleteExpiredAuthRequests(ctx context.Context) (int64, error) {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM auth_requests WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
