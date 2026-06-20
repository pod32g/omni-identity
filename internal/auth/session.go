package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

const sessionCookieName = "omni_session"

// ErrNoSession indicates there is no valid session for the request.
var ErrNoSession = errors.New("auth: no session")

// SessionStore is the persistence surface the SessionManager needs.
type SessionStore interface {
	CreateSession(ctx context.Context, s *model.Session) error
	GetSession(ctx context.Context, id string) (*model.Session, error)
	DeleteSession(ctx context.Context, id string) error
	TouchSession(ctx context.Context, id string, at time.Time) error
}

// SessionConfig supplies the cookie Secure flag, session lifetime, and idle
// timeout at use-time, allowing them to be changed live (e.g. from
// admin-editable settings).
type SessionConfig interface {
	Secure() bool
	Lifetime() time.Duration
	IdleTimeout() time.Duration
}

// SessionManager issues, reads, and destroys browser sessions backed by a store
// and an opaque session cookie.
type SessionManager struct {
	store       SessionStore
	secure      bool
	ttl         time.Duration
	idleTimeout time.Duration // 0 disables idle expiry
	cfg         SessionConfig // when non-nil, overrides the static fields live
}

// NewSessionManager builds a SessionManager. secure controls the cookie Secure
// flag; ttl is the absolute session lifetime.
func NewSessionManager(s SessionStore, secure bool, ttl time.Duration) *SessionManager {
	return &SessionManager{store: s, secure: secure, ttl: ttl}
}

// SetConfigProvider makes the manager read its cookie Secure flag, lifetime, and
// idle timeout from cfg at use-time instead of the static fields.
func (m *SessionManager) SetConfigProvider(cfg SessionConfig) { m.cfg = cfg }

// SetIdleTimeout configures idle-session expiry (0 disables it).
func (m *SessionManager) SetIdleTimeout(d time.Duration) { m.idleTimeout = d }

func (m *SessionManager) secureCookie() bool {
	if m.cfg != nil {
		return m.cfg.Secure()
	}
	return m.secure
}

func (m *SessionManager) lifetime() time.Duration {
	if m.cfg != nil {
		return m.cfg.Lifetime()
	}
	return m.ttl
}

func (m *SessionManager) idle() time.Duration {
	if m.cfg != nil {
		return m.cfg.IdleTimeout()
	}
	return m.idleTimeout
}

// Issue creates a session for userID with the given auth methods (amr),
// persists it, and sets the session cookie. Any session referenced by the
// inbound cookie is deleted first, so the session id rotates on every login and
// a fixated id cannot be reused post-auth.
func (m *SessionManager) Issue(w http.ResponseWriter, r *http.Request, userID, amr string) (*model.Session, error) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		// Best-effort: drop the prior session row before minting a fresh id.
		_ = m.store.DeleteSession(r.Context(), c.Value)
	}
	now := time.Now().UTC()
	sess := &model.Session{
		ID:         uuid.NewString(),
		UserID:     userID,
		CSRFSecret: RandomToken(32),
		UserAgent:  r.UserAgent(),
		CreatedAt:  now,
		ExpiresAt:  now.Add(m.lifetime()),
		LastSeenAt: now,
		AMR:        amr,
	}
	if err := m.store.CreateSession(r.Context(), sess); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(m.lifetime().Seconds()),
	})
	return sess, nil
}

// Current returns the session referenced by the request cookie, or ErrNoSession.
// When an idle timeout is configured, a session whose last activity predates the
// timeout is treated as expired (and deleted). Otherwise the last-seen time is
// refreshed best-effort.
func (m *SessionManager) Current(r *http.Request) (*model.Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}
	sess, err := m.store.GetSession(r.Context(), c.Value)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if m.idle() > 0 {
		last := sess.LastSeenAt
		if last.IsZero() {
			last = sess.CreatedAt
		}
		if now.Sub(last) > m.idle() {
			_ = m.store.DeleteSession(r.Context(), sess.ID)
			return nil, ErrNoSession
		}
		_ = m.store.TouchSession(r.Context(), sess.ID, now)
		sess.LastSeenAt = now
	}
	return sess, nil
}

// Destroy deletes the current session and clears the cookie.
func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if err := m.store.DeleteSession(r.Context(), c.Value); err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}
