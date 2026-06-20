package store

import (
	"context"

	"github.com/pod32g/omni-identity/internal/model"
)

const auditColumns = `id, created_at, event, actor_user_id, username, client_id, ip, user_agent, success, detail`

// AppendAuditEvent records a security event.
func (d *DB) AppendAuditEvent(ctx context.Context, e *model.AuditEvent) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO audit_log (`+auditColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.CreatedAt.UTC(), e.Event, e.ActorUserID, e.Username,
		e.ClientID, e.IP, e.UserAgent, e.Success, e.Detail,
	)
	return err
}

// ListAuditEvents returns the most recent events, newest first, up to limit.
func (d *DB) ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := d.sql.QueryContext(ctx,
		`SELECT `+auditColumns+` FROM audit_log ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.AuditEvent
	for rows.Next() {
		var e model.AuditEvent
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Event, &e.ActorUserID,
			&e.Username, &e.ClientID, &e.IP, &e.UserAgent, &e.Success, &e.Detail); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
