package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const deviceColumns = `id, owner_user_id, name, hostname, platform, architecture, public_key, ` +
	`public_key_algorithm, fingerprint, previous_fingerprint, status, trust_level, ` +
	`created_at, enrolled_at, last_seen_at, revoked_at`

// CreateDevice inserts a new device. The fingerprint must be unique across all
// devices, including revoked ones (a revoked key can never be re-registered).
func (d *DB) CreateDevice(ctx context.Context, dev *model.Device) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO devices (`+deviceColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dev.ID, dev.OwnerUserID, dev.Name, dev.Hostname, dev.Platform, dev.Architecture,
		dev.PublicKey, dev.PublicKeyAlgorithm, dev.Fingerprint, dev.PreviousFingerprint,
		dev.Status, dev.TrustLevel, dev.CreatedAt.UTC(), nullTime(dev.EnrolledAt),
		nullTime(dev.LastSeenAt), nullTime(dev.RevokedAt),
	)
	return err
}

// GetDevice fetches a device by id (any status).
func (d *DB) GetDevice(ctx context.Context, id string) (*model.Device, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id)
	return scanDevice(row)
}

// FingerprintInUse reports whether a key fingerprint is, or ever was, registered
// (current or previous key of any device, regardless of status).
func (d *DB) FingerprintInUse(ctx context.Context, fingerprint string) (bool, error) {
	var n int
	err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE fingerprint = ? OR previous_fingerprint = ?`,
		fingerprint, fingerprint).Scan(&n)
	return n > 0, err
}

// ListDevicesForUser returns a user's devices, newest first.
func (d *DB) ListDevicesForUser(ctx context.Context, userID string) ([]model.Device, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE owner_user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDevices(rows)
}

// ListDevices returns every device, newest first (admin).
func (d *DB) ListDevices(ctx context.Context) ([]model.Device, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDevices(rows)
}

// CountActiveDevices returns the number of active devices (metrics gauge).
func (d *DB) CountActiveDevices(ctx context.Context) (int64, error) {
	var n int64
	err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE status = ?`, model.DeviceStatusActive).Scan(&n)
	return n, err
}

// TouchDevice records a successful device authentication.
func (d *DB) TouchDevice(ctx context.Context, id string, at time.Time) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, at.UTC(), id)
	return err
}

// RevokeDevice marks a device revoked and, in the same transaction, revokes
// every refresh token bound to it. Returns ErrNotFound when the device does not
// exist or is already revoked, so callers can report "already revoked" honestly.
func (d *DB) RevokeDevice(ctx context.Context, id string, at time.Time) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE devices SET status = ?, revoked_at = ? WHERE id = ? AND status <> ?`,
		model.DeviceStatusRevoked, at.UTC(), id, model.DeviceStatusRevoked)
	if err != nil {
		return err
	}
	if err := requireRow(res); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE device_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDevice removes a revoked device row. Active devices must be revoked
// first; deleting one directly returns ErrNotFound.
func (d *DB) DeleteDevice(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM devices WHERE id = ? AND status = ?`, id, model.DeviceStatusRevoked)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// RotateDeviceKey replaces an active device's public key, remembering the
// previous fingerprint. Returns ErrNotFound if the device is not active.
func (d *DB) RotateDeviceKey(ctx context.Context, id, publicKey, alg, fingerprint string) error {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE devices SET previous_fingerprint = fingerprint, public_key = ?,
			public_key_algorithm = ?, fingerprint = ?
		WHERE id = ? AND status = ?`,
		publicKey, alg, fingerprint, id, model.DeviceStatusActive)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// RevokeRefreshTokensForDevice revokes every refresh token bound to a device.
func (d *DB) RevokeRefreshTokensForDevice(ctx context.Context, deviceID string) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = TRUE WHERE device_id = ?`, deviceID)
	return err
}

// ConsumeJTI records a single-use identifier (RFC 7523 assertion jti or DPoP
// proof jti) until expiresAt. It returns false when the identifier was already
// seen, which callers must treat as a replay. Expired rows are pruned first.
func (d *DB) ConsumeJTI(ctx context.Context, jtiHash, deviceID string, expiresAt time.Time) (bool, error) {
	now := time.Now().UTC()
	if _, err := d.sql.ExecContext(ctx,
		`DELETE FROM device_assertion_jtis WHERE expires_at < ?`, now); err != nil {
		return false, err
	}
	// ON CONFLICT DO NOTHING is supported by both SQLite (>= 3.24) and Postgres.
	res, err := d.sql.ExecContext(ctx, `
		INSERT INTO device_assertion_jtis (jti_hash, device_id, expires_at)
		VALUES (?, ?, ?) ON CONFLICT (jti_hash) DO NOTHING`,
		jtiHash, deviceID, expiresAt.UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func collectDevices(rows *sql.Rows) ([]model.Device, error) {
	var out []model.Device
	for rows.Next() {
		dev, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *dev)
	}
	return out, rows.Err()
}

func scanDevice(s scanner) (*model.Device, error) {
	var (
		dev                         model.Device
		enrolled, lastSeen, revoked sql.NullTime
	)
	err := s.Scan(
		&dev.ID, &dev.OwnerUserID, &dev.Name, &dev.Hostname, &dev.Platform, &dev.Architecture,
		&dev.PublicKey, &dev.PublicKeyAlgorithm, &dev.Fingerprint, &dev.PreviousFingerprint,
		&dev.Status, &dev.TrustLevel, &dev.CreatedAt, &enrolled, &lastSeen, &revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if enrolled.Valid {
		dev.EnrolledAt = enrolled.Time
	}
	if lastSeen.Valid {
		dev.LastSeenAt = lastSeen.Time
	}
	if revoked.Valid {
		dev.RevokedAt = revoked.Time
	}
	return &dev, nil
}

// --- RFC 8628 device codes ---

const deviceCodeColumns = `id, device_code_hash, user_code, client_id, scope, device_id, device_name, ` +
	`device_platform, status, user_id, amr, auth_time, last_polled_at, created_at, expires_at`

// CreateDeviceCode stores a pending device authorization grant.
func (d *DB) CreateDeviceCode(ctx context.Context, c *model.DeviceCode) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO device_codes (`+deviceCodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.DeviceCodeHash, c.UserCode, c.ClientID, c.Scope, c.DeviceID, c.DeviceName,
		c.DevicePlatform, c.Status, c.UserID, c.AMR, nullTime(c.AuthTime), nullTime(c.LastPolledAt),
		c.CreatedAt.UTC(), c.ExpiresAt.UTC(),
	)
	return err
}

// GetDeviceCodeByHash fetches a grant by the hash of its device code, in any
// state; the token endpoint decides how to report each state.
func (d *DB) GetDeviceCodeByHash(ctx context.Context, hash string) (*model.DeviceCode, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+deviceCodeColumns+` FROM device_codes WHERE device_code_hash = ?`, hash)
	return scanDeviceCode(row)
}

// GetPendingDeviceCodeByUserCode fetches a pending, unexpired grant by its user
// code (the value the user types on /device).
func (d *DB) GetPendingDeviceCodeByUserCode(ctx context.Context, userCode string) (*model.DeviceCode, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+deviceCodeColumns+` FROM device_codes WHERE user_code = ?`, userCode)
	c, err := scanDeviceCode(row)
	if err != nil {
		return nil, err
	}
	if c.Status != model.DeviceCodePending || time.Now().UTC().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return c, nil
}

// ApproveDeviceCode records the approving user and their session's auth
// details. Only a pending grant can be approved (ErrNotFound otherwise).
func (d *DB) ApproveDeviceCode(ctx context.Context, id, userID, amr string, authTime time.Time) error {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE device_codes SET status = ?, user_id = ?, amr = ?, auth_time = ?
		WHERE id = ? AND status = ?`,
		model.DeviceCodeApproved, userID, amr, authTime.UTC(), id, model.DeviceCodePending)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DenyDeviceCode marks a pending grant denied by the user.
func (d *DB) DenyDeviceCode(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE device_codes SET status = ? WHERE id = ? AND status = ?`,
		model.DeviceCodeDenied, id, model.DeviceCodePending)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// ConsumeDeviceCode atomically moves an approved grant to consumed so the
// device code can be exchanged exactly once. Returns false if it was not in the
// approved state (already consumed, denied, or pending).
func (d *DB) ConsumeDeviceCode(ctx context.Context, id string) (bool, error) {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE device_codes SET status = ? WHERE id = ? AND status = ?`,
		model.DeviceCodeConsumed, id, model.DeviceCodeApproved)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// MarkDeviceCodePolled records the last poll time (slow_down enforcement).
func (d *DB) MarkDeviceCodePolled(ctx context.Context, id string, at time.Time) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE device_codes SET last_polled_at = ? WHERE id = ?`, at.UTC(), id)
	return err
}

// DeleteExpiredDeviceCodes removes grants that expired before now.
func (d *DB) DeleteExpiredDeviceCodes(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM device_codes WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanDeviceCode(s scanner) (*model.DeviceCode, error) {
	var (
		c                  model.DeviceCode
		authTime, lastPoll sql.NullTime
	)
	err := s.Scan(
		&c.ID, &c.DeviceCodeHash, &c.UserCode, &c.ClientID, &c.Scope, &c.DeviceID, &c.DeviceName,
		&c.DevicePlatform, &c.Status, &c.UserID, &c.AMR, &authTime, &lastPoll, &c.CreatedAt, &c.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if authTime.Valid {
		c.AuthTime = authTime.Time
	}
	if lastPoll.Valid {
		c.LastPolledAt = lastPoll.Time
	}
	return &c, nil
}

// PendingUserCodesForTest lists pending, unexpired user codes. It exists only
// so end-to-end tests can approve a grant they did not start; production code
// never enumerates codes.
func (d *DB) PendingUserCodesForTest(ctx context.Context) []string {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT user_code FROM device_codes WHERE status = ? AND expires_at > ?`,
		model.DeviceCodePending, time.Now().UTC())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if rows.Scan(&c) == nil {
			out = append(out, c)
		}
	}
	return out
}
