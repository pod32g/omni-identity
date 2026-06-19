package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const sessionColumns = `id, user_id, csrf_secret, user_agent, created_at, expires_at`

// CreateSession inserts a new browser session.
func (d *DB) CreateSession(ctx context.Context, s *model.Session) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO sessions (`+sessionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.CSRFSecret, s.UserAgent,
		s.CreatedAt.UTC(), s.ExpiresAt.UTC(),
	)
	return err
}

// GetSession returns the session, or ErrNotFound if it is missing or expired.
func (d *DB) GetSession(ctx context.Context, id string) (*model.Session, error) {
	row := d.sql.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id)
	s, err := scanSession(row)
	if err != nil {
		return nil, err
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, ErrNotFound
	}
	return s, nil
}

// DeleteSession removes a session (logout). Missing sessions are not an error.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteExpiredSessions removes sessions that expired before now.
func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanSession(s scanner) (*model.Session, error) {
	var sess model.Session
	err := s.Scan(
		&sess.ID, &sess.UserID, &sess.CSRFSecret, &sess.UserAgent,
		&sess.CreatedAt, &sess.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}
