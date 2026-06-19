package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const clientColumns = `client_id, client_secret_hash, name, redirect_uris, allowed_scopes, type, disabled, created_at, updated_at`

// CreateClient inserts a new client.
func (d *DB) CreateClient(ctx context.Context, c *model.Client) error {
	redirects, scopes := encodeStrings(c.RedirectURIs), encodeStrings(c.AllowedScopes)
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO clients (`+clientColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ClientID, c.ClientSecretHash, c.Name, redirects, scopes,
		c.Type, c.Disabled, c.CreatedAt.UTC(), c.UpdatedAt.UTC(),
	)
	return err
}

// GetClient fetches a client by id.
func (d *DB) GetClient(ctx context.Context, clientID string) (*model.Client, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+clientColumns+` FROM clients WHERE client_id = ?`, clientID)
	return scanClient(row)
}

// ListClients returns all clients ordered by creation time.
func (d *DB) ListClients(ctx context.Context) ([]model.Client, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+clientColumns+` FROM clients ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []model.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *c)
	}
	return clients, rows.Err()
}

// UpdateClient updates name, redirect URIs, allowed scopes, type, and disabled.
func (d *DB) UpdateClient(ctx context.Context, c *model.Client) error {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE clients SET name = ?, redirect_uris = ?, allowed_scopes = ?,
			type = ?, disabled = ?, updated_at = ?
		WHERE client_id = ?`,
		c.Name, encodeStrings(c.RedirectURIs), encodeStrings(c.AllowedScopes),
		c.Type, c.Disabled, time.Now().UTC(), c.ClientID,
	)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetClientSecretHash replaces a client's secret hash (rotation).
func (d *DB) SetClientSecretHash(ctx context.Context, clientID, hash string) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE clients SET client_secret_hash = ?, updated_at = ? WHERE client_id = ?`,
		hash, time.Now().UTC(), clientID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetClientDisabled enables or disables a client.
func (d *DB) SetClientDisabled(ctx context.Context, clientID string, disabled bool) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE clients SET disabled = ?, updated_at = ? WHERE client_id = ?`,
		disabled, time.Now().UTC(), clientID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func scanClient(s scanner) (*model.Client, error) {
	var (
		c                 model.Client
		redirects, scopes string
	)
	err := s.Scan(
		&c.ClientID, &c.ClientSecretHash, &c.Name, &redirects, &scopes,
		&c.Type, &c.Disabled, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = decodeStrings(redirects)
	c.AllowedScopes = decodeStrings(scopes)
	return &c, nil
}

func encodeStrings(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

func decodeStrings(s string) []string {
	var ss []string
	if s == "" {
		return nil
	}
	_ = json.Unmarshal([]byte(s), &ss)
	return ss
}
