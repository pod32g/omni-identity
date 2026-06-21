package web

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

// Audit event names.
const (
	evtLoginSuccess    = "login.success"
	evtLoginFailed     = "login.failed"
	evtLoginLocked     = "login.locked"
	evtLogout          = "logout"
	evtMFAChallenge    = "mfa.challenge"
	evtMFASuccess      = "mfa.success"
	evtMFAFailed       = "mfa.failed"
	evtMFAEnrolled     = "mfa.enrolled"
	evtMFADisabled     = "mfa.disabled"
	evtMFAReset        = "mfa.reset"
	evtConsentGranted  = "consent.granted"
	evtConsentDenied   = "consent.denied"
	evtTokenIssued     = "token.issued"
	evtTokenRevoked    = "token.revoked"
	evtPasswordChange  = "password.change"
	evtUserInvited     = "admin.user.invited"
	evtResetLinkIssued = "password.reset_link_issued"
	evtResetRequested  = "password.reset_requested"
	evtPasswordSetTok  = "password.set_via_token"
	evtUserCreated     = "admin.user.created"
	evtUserDisabled    = "admin.user.disabled"
	evtUserUnlocked    = "admin.user.unlocked"
	evtClientCreated   = "admin.client.created"
	evtClientUpdated   = "admin.client.updated"
	evtClientSecret    = "admin.client.secret_rotated"
	evtBrandingUpdate  = "admin.branding.updated"
	evtSettingsUpdated = "admin.settings.updated"
	evtSessionsRevoked = "session.revoked_all"
)

// auditEntry carries the variable fields of an audit record.
type auditEntry struct {
	actorUserID string
	username    string
	clientID    string
	success     bool
	detail      string
}

// audit records a security event (best-effort: failures are logged, not fatal).
func (s *Server) audit(r *http.Request, event string, e auditEntry) {
	ev := &model.AuditEvent{
		ID:          uuid.NewString(),
		CreatedAt:   time.Now().UTC(),
		Event:       event,
		ActorUserID: e.actorUserID,
		Username:    e.username,
		ClientID:    e.clientID,
		IP:          clientIP(r),
		UserAgent:   r.UserAgent(),
		Success:     e.success,
		Detail:      e.detail,
	}
	// Surface the event on the structured log stream too (this is the useful,
	// security-relevant signal that ships to omnilog — logins, MFA, lockouts,
	// token issuance, consent, and admin actions — not just raw HTTP requests).
	logAuditEvent(ev)

	// Use a detached context so logging survives a cancelled request.
	if err := s.db.AppendAuditEvent(context.Background(), ev); err != nil {
		slog.Error("audit append failed", "event", event, "error", err.Error())
	}
}

// logAuditEvent emits one structured log line per audit event. Failed/locked/
// denied events are logged at WARN so operators can filter to just the problems;
// everything else is INFO. The message is the event name (e.g. "login.success")
// and the fields are searchable in omnilog.
func logAuditEvent(ev *model.AuditEvent) {
	args := make([]any, 0, 12)
	args = append(args, "event", ev.Event, "success", ev.Success)
	if ev.Username != "" {
		args = append(args, "username", ev.Username)
	}
	if ev.ActorUserID != "" {
		args = append(args, "actor", ev.ActorUserID)
	}
	if ev.ClientID != "" {
		args = append(args, "client_id", ev.ClientID)
	}
	if ev.IP != "" {
		args = append(args, "ip", ev.IP)
	}
	if ev.Detail != "" {
		args = append(args, "detail", ev.Detail)
	}
	slog.Default().Log(context.Background(), auditLevel(ev.Event), ev.Event, args...)
}

// auditLevel maps an audit event to a log level.
func auditLevel(event string) slog.Level {
	switch event {
	case evtLoginFailed, evtLoginLocked, evtMFAFailed, evtConsentDenied:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}
