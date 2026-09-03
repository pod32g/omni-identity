package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const webauthnColumns = `id, user_id, name, credential, aaguid, backup_eligible, created_at, last_used_at`

// CreateWebAuthnCredential stores a newly registered passkey.
func (d *DB) CreateWebAuthnCredential(ctx context.Context, c *model.WebAuthnCredential) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (`+webauthnColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Name, c.Credential, c.AAGUID, c.BackupEligible, c.CreatedAt.UTC(), nullTime(c.LastUsedAt))
	return err
}

// GetWebAuthnCredential fetches a credential by its id.
func (d *DB) GetWebAuthnCredential(ctx context.Context, id string) (*model.WebAuthnCredential, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT `+webauthnColumns+` FROM webauthn_credentials WHERE id = ?`, id)
	return scanWebAuthnCredential(row)
}

// ListWebAuthnCredentials returns a user's passkeys, oldest first.
func (d *DB) ListWebAuthnCredentials(ctx context.Context, userID string) ([]model.WebAuthnCredential, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+webauthnColumns+` FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// CountWebAuthnCredentials returns how many passkeys a user has.
func (d *DB) CountWebAuthnCredentials(ctx context.Context, userID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// UpdateWebAuthnCredential stores the post-authentication credential record
// (sign counter, flags) and the last-used time.
func (d *DB) UpdateWebAuthnCredential(ctx context.Context, id, credential string, usedAt time.Time) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE webauthn_credentials SET credential = ?, last_used_at = ? WHERE id = ?`,
		credential, usedAt.UTC(), id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DeleteWebAuthnCredential removes one of a user's passkeys. ErrNotFound when
// the id does not belong to the user.
func (d *DB) DeleteWebAuthnCredential(ctx context.Context, userID, id string) error {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DeleteWebAuthnCredentialsForUser removes every passkey of a user (admin reset).
func (d *DB) DeleteWebAuthnCredentialsForUser(ctx context.Context, userID string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetUserWebAuthnHandle assigns the opaque user handle (first registration).
func (d *DB) SetUserWebAuthnHandle(ctx context.Context, userID, handle string) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE users SET webauthn_handle = ? WHERE id = ? AND webauthn_handle = ''`, handle, userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// GetUserByWebAuthnHandle resolves the user behind an authenticator-reported
// user handle (discoverable login).
func (d *DB) GetUserByWebAuthnHandle(ctx context.Context, handle string) (*model.User, error) {
	if handle == "" {
		return nil, ErrNotFound
	}
	row := d.sql.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE webauthn_handle = ?`, handle)
	return scanUser(row)
}

func scanWebAuthnCredential(s scanner) (*model.WebAuthnCredential, error) {
	var (
		c        model.WebAuthnCredential
		lastUsed sql.NullTime
	)
	err := s.Scan(&c.ID, &c.UserID, &c.Name, &c.Credential, &c.AAGUID, &c.BackupEligible, &c.CreatedAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		c.LastUsedAt = lastUsed.Time
	}
	return &c, nil
}

// --- ceremonies ---

// CreateWebAuthnCeremony stores a pending begin→finish ceremony.
func (d *DB) CreateWebAuthnCeremony(ctx context.Context, c *model.WebAuthnCeremony) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO webauthn_ceremonies (id, user_id, purpose, session_data, next, req, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Purpose, c.SessionData, c.Next, c.Req, c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	return err
}

// ConsumeWebAuthnCeremony fetches and deletes a ceremony in one transaction so
// a challenge can be answered exactly once. Expired ceremonies are ErrNotFound.
func (d *DB) ConsumeWebAuthnCeremony(ctx context.Context, id string) (*model.WebAuthnCeremony, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx,
		`SELECT id, user_id, purpose, session_data, next, req, created_at, expires_at FROM webauthn_ceremonies WHERE id = ?`, id)
	var c model.WebAuthnCeremony
	err = row.Scan(&c.ID, &c.UserID, &c.Purpose, &c.SessionData, &c.Next, &c.Req, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM webauthn_ceremonies WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	if err := requireRow(res); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &c, nil
}

// DeleteExpiredWebAuthnCeremonies prunes stale ceremonies.
func (d *DB) DeleteExpiredWebAuthnCeremonies(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM webauthn_ceremonies WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
