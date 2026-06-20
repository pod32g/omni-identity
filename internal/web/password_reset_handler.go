package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

const (
	activationTokenTTL = 72 * time.Hour
	resetTokenTTL      = 1 * time.Hour
)

// issuePasswordToken creates a single-use token for userID and returns the
// shareable link (built from the live public URL).
func (s *Server) issuePasswordToken(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	raw := auth.RandomToken(32)
	now := time.Now().UTC()
	tok := &model.PasswordToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: auth.HashToken(raw),
		Purpose:   purpose,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := s.db.CreatePasswordToken(ctx, tok); err != nil {
		return "", err
	}
	base := strings.TrimRight(s.settings.Current().PublicURL, "/")
	return base + "/set-password?token=" + raw, nil
}

type setPasswordPage struct {
	CSRFToken string
	Token     string
	Policy    string
	Error     string
}

func (s *Server) renderSetPassword(w http.ResponseWriter, r *http.Request, status int, token, errMsg string) {
	s.tmpl.render(w, status, "set_password", setPasswordPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Token:     token,
		Policy:    s.passwordPolicy().Describe(),
		Error:     errMsg,
	})
}

// handleSetPasswordForm renders the set-password page for a valid token.
func (s *Server) handleSetPasswordForm(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		s.renderError(w, http.StatusBadRequest, "This password link is missing its token.")
		return
	}
	if _, err := s.db.GetValidPasswordToken(r.Context(), auth.HashToken(raw)); err != nil {
		s.renderError(w, http.StatusBadRequest, "This password link is invalid or has expired. Ask an administrator for a new one.")
		return
	}
	s.renderSetPassword(w, r, http.StatusOK, raw, "")
}

// handleSetPasswordSubmit consumes the token and sets the user's password.
func (s *Server) handleSetPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	raw := r.PostFormValue("token")
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")

	// Validate the token (without consuming) so a typo doesn't burn it.
	tok, err := s.db.GetValidPasswordToken(r.Context(), auth.HashToken(raw))
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "This password link is invalid or has expired. Ask an administrator for a new one.")
		return
	}
	user, err := s.db.GetUserByID(r.Context(), tok.UserID)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "This account is no longer available.")
		return
	}
	if password != confirm {
		s.renderSetPassword(w, r, http.StatusBadRequest, raw, "The two passwords don't match.")
		return
	}
	if msg := auth.ValidatePassword(password, user.Username, user.Email, s.passwordPolicy()); msg != "" {
		s.renderSetPassword(w, r, http.StatusBadRequest, raw, msg)
		return
	}

	// Atomically consume the token; lose the race -> treat as invalid.
	if _, ok, err := s.db.ConsumePasswordToken(r.Context(), auth.HashToken(raw)); err != nil || !ok {
		s.renderError(w, http.StatusBadRequest, "This password link is invalid or has expired.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.db.SetUserPassword(r.Context(), user.ID, hash); err != nil {
		http.Error(w, "could not set password", http.StatusInternalServerError)
		return
	}
	// Invalidate any other outstanding tokens and all sessions for the account.
	_ = s.db.DeletePasswordTokensForUser(r.Context(), user.ID)
	_, _ = s.db.DeleteSessionsForUser(r.Context(), user.ID, "")
	s.audit(r, evtPasswordSetTok, auditEntry{actorUserID: user.ID, username: user.Username, success: true, detail: tok.Purpose})

	http.Redirect(w, r, "/login?notice=password-set", http.StatusSeeOther)
}

// handleAdminUserResetLink issues a reset link for a user (admin action).
func (s *Server) handleAdminUserResetLink(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	user, err := s.db.GetUserByID(r.Context(), id)
	if err != nil {
		s.renderUsers(w, r, http.StatusNotFound, "User not found.")
		return
	}
	link, err := s.issuePasswordToken(r.Context(), user.ID, model.PasswordTokenReset, resetTokenTTL)
	if err != nil {
		s.renderUsers(w, r, http.StatusInternalServerError, "Could not create a reset link.")
		return
	}
	s.audit(r, evtResetLinkIssued, auditEntry{actorUserID: actorID(r), username: user.Username, success: true, detail: "id=" + id})
	s.renderUsersWithLink(w, r, link, "Reset link for "+user.Username+" (valid 1 hour, single use):")
}
