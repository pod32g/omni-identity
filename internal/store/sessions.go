package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

const sessionColumns = `id, user_id, csrf_secret, user_agent, created_at, expires_at, last_seen_at, amr`

// CreateSession inserts a new browser session.
func (d *DB) CreateSession(ctx context.Context, s *model.Session) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO sessions (`+sessionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.CSRFSecret, s.UserAgent,
		s.CreatedAt.UTC(), s.ExpiresAt.UTC(), nullTime(s.LastSeenAt), s.AMR,
	)
	return err
}

// TouchSession updates the last-seen timestamp (idle-timeout tracking).
func (d *DB) TouchSession(ctx context.Context, id string, at time.Time) error {
	_, err := d.sql.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, at.UTC(), id)
	return err
}

// ListSessionsForUser returns a user's non-expired sessions, newest first.
func (d *DB) ListSessionsForUser(ctx context.Context, userID string) ([]model.Session, error) {
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`,
		userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// DeleteSessionsForUser removes every session for a user except optional
// keepID (used for "sign out everywhere else"). Returns the count removed.
func (d *DB) DeleteSessionsForUser(ctx context.Context, userID, keepID string) (int64, error) {
	res, err := d.sql.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, keepID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountActiveSessions returns the number of non-expired browser sessions.
func (d *DB) CountActiveSessions(ctx context.Context) (int64, error) {
	var n int64
	err := d.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM sessions WHERE expires_at > ?`, time.Now().UTC()).Scan(&n)
	return n, err
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
	var (
		sess     model.Session
		lastSeen sql.NullTime
	)
	err := s.Scan(
		&sess.ID, &sess.UserID, &sess.CSRFSecret, &sess.UserAgent,
		&sess.CreatedAt, &sess.ExpiresAt, &lastSeen, &sess.AMR,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		sess.LastSeenAt = lastSeen.Time
	}
	return &sess, nil
}
