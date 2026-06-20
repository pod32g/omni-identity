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
	evtUserCreated     = "admin.user.created"
	evtUserDisabled    = "admin.user.disabled"
	evtUserUnlocked    = "admin.user.unlocked"
	evtClientCreated   = "admin.client.created"
	evtClientUpdated   = "admin.client.updated"
	evtClientSecret    = "admin.client.secret_rotated"
	evtBrandingUpdate  = "admin.branding.updated"
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
	// Use a detached context so logging survives a cancelled request.
	if err := s.db.AppendAuditEvent(context.Background(), ev); err != nil {
		slog.Error("audit append failed", "event", event, "error", err.Error())
	}
}
