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
}

// SessionManager issues, reads, and destroys browser sessions backed by a store
// and an opaque session cookie.
type SessionManager struct {
	store  SessionStore
	secure bool
	ttl    time.Duration
}

// NewSessionManager builds a SessionManager. secure controls the cookie Secure
// flag; ttl is the session lifetime.
func NewSessionManager(s SessionStore, secure bool, ttl time.Duration) *SessionManager {
	return &SessionManager{store: s, secure: secure, ttl: ttl}
}

// Issue creates a session for userID, persists it, and sets the session cookie.
// Any session referenced by the inbound cookie is deleted first, so the session
// id rotates on every login and a fixated id cannot be reused post-auth.
func (m *SessionManager) Issue(w http.ResponseWriter, r *http.Request, userID string) (*model.Session, error) {
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
		ExpiresAt:  now.Add(m.ttl),
	}
	if err := m.store.CreateSession(r.Context(), sess); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(m.ttl.Seconds()),
	})
	return sess, nil
}

// Current returns the session referenced by the request cookie, or ErrNoSession.
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
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}
