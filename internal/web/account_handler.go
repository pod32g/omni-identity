package web

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// requireUser wraps a handler so only authenticated (non-disabled) users may
// reach it. Unlike requireAdmin it does not require the admin flag.
func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.sessions.Current(r)
		if err != nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		user, err := s.db.GetUserByID(r.Context(), sess.UserID)
		if err != nil || user.Disabled {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		ctx = context.WithValue(ctx, sessCtxKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func currentSession(r *http.Request) *model.Session {
	s, _ := r.Context().Value(sessCtxKey).(*model.Session)
	return s
}

type accountPage struct {
	CSRFToken      string
	Me             *model.User
	Active         string
	MFAEnabled     bool
	Sessions       []sessionView
	CurrentSession string
	Error          string
	Saved          string
}

type sessionView struct {
	ID        string
	UserAgent string
	CreatedAt string
	Current   bool
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, errMsg, saved string) {
	user := currentUser(r)
	cur := currentSession(r)
	sessions, _ := s.db.ListSessionsForUser(r.Context(), user.ID)
	views := make([]sessionView, 0, len(sessions))
	for _, ss := range sessions {
		views = append(views, sessionView{
			ID:        ss.ID,
			UserAgent: ss.UserAgent,
			CreatedAt: ss.CreatedAt.Format("2006-01-02 15:04 MST"),
			Current:   cur != nil && ss.ID == cur.ID,
		})
	}
	s.tmpl.render(w, status, "account", accountPage{
		CSRFToken:  auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:         user,
		Active:     "account",
		MFAEnabled: user.MFAEnabled,
		Sessions:   views,
		CurrentSession: func() string {
			if cur != nil {
				return cur.ID
			}
			return ""
		}(),
		Error: errMsg,
		Saved: saved,
	})
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, "", "")
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	current := r.PostFormValue("current_password")
	next := r.PostFormValue("new_password")

	// Re-authenticate with the current password before allowing a change.
	if ok, _ := auth.VerifyPassword(current, user.PasswordHash); !ok {
		s.renderAccount(w, r, http.StatusUnauthorized, "Your current password is incorrect.", "")
		return
	}
	if msg := auth.ValidatePassword(next, user.Username, user.Email, s.cfg.Security.PasswordMinLength); msg != "" {
		s.renderAccount(w, r, http.StatusBadRequest, msg, "")
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.db.SetUserPassword(r.Context(), user.ID, hash); err != nil {
		s.renderAccount(w, r, http.StatusInternalServerError, "Could not change password.", "")
		return
	}
	// Invalidate other sessions after a password change.
	if cur := currentSession(r); cur != nil {
		_, _ = s.db.DeleteSessionsForUser(r.Context(), user.ID, cur.ID)
	}
	s.audit(r, evtPasswordChange, auditEntry{actorUserID: user.ID, username: user.Username, success: true})
	s.renderAccount(w, r, http.StatusOK, "", "Password changed. Other sessions were signed out.")
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	keep := ""
	if cur := currentSession(r); cur != nil {
		keep = cur.ID
	}
	n, err := s.db.DeleteSessionsForUser(r.Context(), user.ID, keep)
	if err != nil {
		s.renderAccount(w, r, http.StatusInternalServerError, "Could not revoke sessions.", "")
		return
	}
	s.audit(r, evtSessionsRevoked, auditEntry{actorUserID: user.ID, username: user.Username, success: true, detail: "revoked other sessions"})
	_ = n
	s.renderAccount(w, r, http.StatusOK, "", "Signed out of all other sessions.")
}

// newRecoveryCodeSet generates n plaintext recovery codes and their hashed,
// storable records.
func newRecoveryCodeSet(n int) ([]string, []model.RecoveryCode) {
	now := time.Now().UTC()
	plain := make([]string, 0, n)
	records := make([]model.RecoveryCode, 0, n)
	for i := 0; i < n; i++ {
		code := auth.RandomToken(5) // ~8 chars base32-ish
		plain = append(plain, code)
		records = append(records, model.RecoveryCode{
			ID:        uuid.NewString(),
			CodeHash:  auth.HashToken(normalizeRecovery(code)),
			CreatedAt: now,
		})
	}
	return plain, records
}
