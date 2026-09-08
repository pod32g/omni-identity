package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const patColumns = `id, user_id, device_id, client_id, name, scope, created_at, expires_at, last_used_at, revoked_at`

// CreatePAT records a newly issued personal access token.
func (d *DB) CreatePAT(ctx context.Context, p *model.PersonalAccessToken) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO personal_access_tokens (`+patColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.DeviceID, p.ClientID, p.Name, p.Scope,
		p.CreatedAt.UTC(), p.ExpiresAt.UTC(), nullTime(ptrTime(p.LastUsedAt)), nullTime(ptrTime(p.RevokedAt)),
	)
	return err
}

// GetPAT fetches one token by id.
func (d *DB) GetPAT(ctx context.Context, id string) (*model.PersonalAccessToken, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT `+patColumns+` FROM personal_access_tokens WHERE id = ?`, id)
	return scanPAT(row)
}

// ListActivePATsForDevice returns a device's tokens that are neither revoked
// nor expired, newest first — what the client's Tokens screen manages.
func (d *DB) ListActivePATsForDevice(ctx context.Context, deviceID string) ([]model.PersonalAccessToken, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+patColumns+`
		FROM personal_access_tokens
		WHERE device_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at DESC`, deviceID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.PersonalAccessToken
	for rows.Next() {
		p, err := scanPAT(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// RevokePATForDevice revokes one token if it belongs to the device and is not
// already revoked. Returns whether a row was affected.
func (d *DB) RevokePATForDevice(ctx context.Context, id, deviceID string) (bool, error) {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE personal_access_tokens SET revoked_at = ? WHERE id = ? AND device_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id, deviceID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RevokePATsForDevice revokes every active token of a device (device unenroll
// or revoke). RevokePATsForUser does the same for a user (disable or delete).
func (d *DB) RevokePATsForDevice(ctx context.Context, deviceID string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE personal_access_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), deviceID)
	return err
}

func (d *DB) RevokePATsForUser(ctx context.Context, userID string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE personal_access_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), userID)
	return err
}

// RevokedPATJTIs returns the ids of revoked tokens that have not yet expired —
// the set a resource server must reject. Expired ones drop out on their own.
func (d *DB) RevokedPATJTIs(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT id FROM personal_access_tokens WHERE revoked_at IS NOT NULL AND expires_at > ?`, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func scanPAT(row interface{ Scan(...any) error }) (*model.PersonalAccessToken, error) {
	var p model.PersonalAccessToken
	var lastUsed, revoked sql.NullTime
	if err := row.Scan(&p.ID, &p.UserID, &p.DeviceID, &p.ClientID, &p.Name, &p.Scope,
		&p.CreatedAt, &p.ExpiresAt, &lastUsed, &revoked); err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		p.LastUsedAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		p.RevokedAt = &t
	}
	return &p, nil
}

func ptrTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
