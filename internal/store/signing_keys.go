package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pod32g/omni-identity/internal/model"
)

const signingKeyColumns = `kid, alg, public_jwk, private_pem, active, created_at`

// CreateSigningKey inserts a signing key.
func (d *DB) CreateSigningKey(ctx context.Context, k *model.SigningKey) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO signing_keys (`+signingKeyColumns+`)
		VALUES (?, ?, ?, ?, ?, ?)`,
		k.KID, k.Alg, k.PublicJWK, k.PrivatePEM, k.Active, k.CreatedAt.UTC(),
	)
	return err
}

// ListSigningKeys returns all signing keys, newest first.
func (d *DB) ListSigningKeys(ctx context.Context) ([]model.SigningKey, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []model.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *k)
	}
	return keys, rows.Err()
}

// GetActiveSigningKey returns the newest active key for the given algorithm.
func (d *DB) GetActiveSigningKey(ctx context.Context, alg string) (*model.SigningKey, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT `+signingKeyColumns+` FROM signing_keys
		WHERE alg = ? AND active = 1
		ORDER BY created_at DESC LIMIT 1`, alg)
	return scanSigningKey(row)
}

func scanSigningKey(s scanner) (*model.SigningKey, error) {
	var k model.SigningKey
	err := s.Scan(&k.KID, &k.Alg, &k.PublicJWK, &k.PrivatePEM, &k.Active, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}
