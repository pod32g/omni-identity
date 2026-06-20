package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// forgotEnabled reports whether self-service email password reset is available.
func (s *Server) forgotEnabled() bool { return s.mailer != nil && s.mailer.Enabled() }

type forgotPage struct {
	CSRFToken string
	Error     string
	Sent      bool
}

func (s *Server) handleForgotForm(w http.ResponseWriter, r *http.Request) {
	if !s.forgotEnabled() {
		s.renderError(w, http.StatusNotFound, "Password reset by email isn't enabled. Please contact an administrator.")
		return
	}
	s.tmpl.render(w, http.StatusOK, "forgot", forgotPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
	})
}

func (s *Server) handleForgotSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.forgotEnabled() {
		s.renderError(w, http.StatusNotFound, "Password reset by email isn't enabled.")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	identifier := strings.TrimSpace(r.PostFormValue("identifier"))
	// Rate-limit by IP to blunt enumeration/spam; always show the same result.
	if s.forgotRate.Allowed(clientIP(r)) {
		s.forgotRate.Fail(clientIP(r))
		go s.dispatchReset(identifier, clientIP(r), r.UserAgent())
	}
	s.audit(r, evtResetRequested, auditEntry{detail: "self-service forgot-password"})

	// Identical response whether or not the account exists (no enumeration).
	s.tmpl.render(w, http.StatusOK, "forgot", forgotPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Sent:      true,
	})
}

// dispatchReset looks up the user (by username or email), and if found, issues a
// reset token and emails the link. Runs in the background so the HTTP response
// timing does not reveal whether the account exists.
func (s *Server) dispatchReset(identifier, ip, ua string) {
	ctx := context.Background()
	user := s.lookupUser(ctx, identifier)
	if user == nil || user.Disabled || !user.IsLocal() {
		// Silent: no enumeration. Directory-managed (e.g. LDAP) accounts have no
		// local password to reset, so we issue no token or email for them either.
		return
	}
	link, err := s.issuePasswordToken(ctx, user.ID, model.PasswordTokenReset, resetTokenTTL)
	if err != nil {
		slog.Error("forgot: issue token", "error", err.Error())
		return
	}
	body := "Hello,\n\nA password reset was requested for your account. " +
		"Use the link below to choose a new password. It is valid for 1 hour and can be used once.\n\n" +
		link + "\n\nIf you did not request this, you can ignore this message.\n"
	if err := s.mailer.Send(user.Email, "Reset your password", body); err != nil {
		slog.Error("forgot: send email", "error", err.Error())
	}
}

// lookupUser resolves an account by username or email.
func (s *Server) lookupUser(ctx context.Context, identifier string) *model.User {
	if identifier == "" {
		return nil
	}
	if u, err := s.db.GetUserByUsername(ctx, identifier); err == nil {
		return u
	}
	if u, err := s.db.GetUserByEmail(ctx, identifier); err == nil {
		return u
	}
	return nil
}
