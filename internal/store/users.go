package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

const userColumns = `id, username, email, password_hash, is_admin, disabled, ` +
	`failed_login_count, locked_until, mfa_enabled, totp_secret, ` +
	`auth_source, external_id, created_at, updated_at`

// CreateUser inserts a new user.
func (d *DB) CreateUser(ctx context.Context, u *model.User) error {
	if u.AuthSource == "" {
		u.AuthSource = "local"
	}
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO users (`+userColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.IsAdmin, u.Disabled,
		u.FailedLoginCount, nullTime(u.LockedUntil), u.MFAEnabled, u.TOTPSecret,
		u.AuthSource, u.ExternalID, u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
	)
	return err
}

// GetUserByID fetches a user by id.
func (d *DB) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// GetUserByUsername fetches a user by username.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// GetUserByEmail fetches a user by email.
func (d *DB) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, email)
	return scanUser(row)
}

// GetUserByExternalID fetches a user by (auth_source, external_id).
func (d *DB) GetUserByExternalID(ctx context.Context, source, externalID string) (*model.User, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE auth_source = ? AND external_id = ?`,
		source, externalID)
	return scanUser(row)
}

// UpsertExternalUser provisions or refreshes the local mirror of a user
// authenticated by an external connector (e.g. LDAP). It matches on
// (auth_source, external_id): on first login it inserts a new passwordless row;
// otherwise it refreshes the mutable profile (email) and the admin flag. It
// refuses to shadow an existing *local* account with the same username, so a
// directory entry can never silently take over or escalate a local login.
func (d *DB) UpsertExternalUser(ctx context.Context, source, externalID, username, email, displayName string, isAdmin bool) (*model.User, error) {
	now := time.Now().UTC()
	existing, err := d.GetUserByExternalID(ctx, source, externalID)
	switch {
	case err == nil:
		res, uerr := d.sql.ExecContext(ctx,
			`UPDATE users SET email = ?, is_admin = ?, updated_at = ? WHERE id = ?`,
			email, isAdmin, now, existing.ID)
		if uerr != nil {
			return nil, uerr
		}
		if uerr := requireRow(res); uerr != nil {
			return nil, uerr
		}
		existing.Email = email
		existing.IsAdmin = isAdmin
		existing.UpdatedAt = now
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}

	// First login: guard against shadowing a local account of the same username.
	if local, lerr := d.GetUserByUsername(ctx, username); lerr == nil && local.IsLocal() {
		return nil, fmt.Errorf("external user %q collides with an existing local account", username)
	}
	u := &model.User{
		ID:         uuid.NewString(),
		Username:   username,
		Email:      email,
		IsAdmin:    isAdmin,
		AuthSource: source,
		ExternalID: externalID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := d.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// UpdateUser updates the mutable profile fields (email, is_admin, disabled).
func (d *DB) UpdateUser(ctx context.Context, u *model.User) error {
	res, err := d.sql.ExecContext(ctx, `
		UPDATE users SET email = ?, is_admin = ?, disabled = ?, updated_at = ?
		WHERE id = ?`,
		u.Email, u.IsAdmin, u.Disabled, time.Now().UTC(), u.ID,
	)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetUserPassword replaces a user's password hash.
func (d *DB) SetUserPassword(ctx context.Context, id, passwordHash string) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetUserDisabled enables or disables a user account.
func (d *DB) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := d.sql.ExecContext(ctx,
		`UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`,
		disabled, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DeleteUser permanently removes a user row. Callers should clear the user's
// sessions first; audit rows reference the username/actor as plain strings (no
// foreign key), so they survive deletion as a historical record. Returns
// ErrNotFound when no row matched.
func (d *DB) DeleteUser(ctx context.Context, id string) error {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// CountAdmins returns the number of enabled admin users.
func (d *DB) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM users WHERE is_admin = TRUE AND disabled = FALSE`).Scan(&n)
	return n, err
}

// ListUsers returns all users ordered by creation time.
func (d *DB) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func scanUser(s scanner) (*model.User, error) {
	var (
		u           model.User
		lockedUntil sql.NullTime
	)
	err := s.Scan(
		&u.ID, &u.Username, &u.Email, &u.PasswordHash,
		&u.IsAdmin, &u.Disabled, &u.FailedLoginCount, &lockedUntil,
		&u.MFAEnabled, &u.TOTPSecret, &u.AuthSource, &u.ExternalID,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lockedUntil.Valid {
		u.LockedUntil = lockedUntil.Time
	}
	return &u, nil
}

// nullTime maps a zero time.Time to SQL NULL.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// requireRow converts a zero-rows-affected result into ErrNotFound.
func requireRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
