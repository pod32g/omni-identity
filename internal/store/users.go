package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const userColumns = `id, username, email, password_hash, is_admin, disabled, ` +
	`failed_login_count, locked_until, mfa_enabled, totp_secret, created_at, updated_at`

// CreateUser inserts a new user.
func (d *DB) CreateUser(ctx context.Context, u *model.User) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO users (`+userColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.IsAdmin, u.Disabled,
		u.FailedLoginCount, nullTime(u.LockedUntil), u.MFAEnabled, u.TOTPSecret,
		u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
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
		&u.MFAEnabled, &u.TOTPSecret, &u.CreatedAt, &u.UpdatedAt,
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
