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

type loginPage struct {
	CSRFToken string
	Error     string
	Next      string
}

type setupPage struct {
	CSRFToken string
	Error     string
	Username  string
	Email     string
}

// needsSetup reports whether no enabled admin exists yet.
func (s *Server) needsSetup(ctx context.Context) bool {
	n, err := s.db.CountAdmins(ctx)
	return err == nil && n == 0
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.needsSetup(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	token := auth.CSRFToken(w, r, s.cfg.Cookies.Secure)
	s.tmpl.render(w, http.StatusOK, "login", loginPage{
		CSRFToken: token,
		Next:      safeNext(r.URL.Query().Get("next")),
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	user, err := auth.Authenticate(r.Context(), s.db,
		r.PostFormValue("username"), r.PostFormValue("password"))
	if err != nil {
		token := auth.CSRFToken(w, r, s.cfg.Cookies.Secure)
		s.tmpl.render(w, http.StatusUnauthorized, "login", loginPage{
			CSRFToken: token,
			Error:     "Invalid username or password.",
			Next:      safeNext(r.PostFormValue("next")),
		})
		return
	}

	if _, err := s.sessions.Issue(w, r, user.ID); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}

	dest := safeNext(r.PostFormValue("next"))
	if dest == "" {
		dest = "/admin"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := s.sessions.Destroy(w, r); err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if !s.needsSetup(r.Context()) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	token := auth.CSRFToken(w, r, s.cfg.Cookies.Secure)
	s.tmpl.render(w, http.StatusOK, "setup", setupPage{CSRFToken: token})
}

func (s *Server) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	// Block the wizard entirely once an admin exists.
	if !s.needsSetup(r.Context()) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	username := strings.TrimSpace(r.PostFormValue("username"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")

	reRender := func(msg string) {
		token := auth.CSRFToken(w, r, s.cfg.Cookies.Secure)
		s.tmpl.render(w, http.StatusBadRequest, "setup", setupPage{
			CSRFToken: token, Error: msg, Username: username, Email: email,
		})
	}

	if username == "" || email == "" {
		reRender("Username and email are required.")
		return
	}
	if len(password) < 8 {
		reRender("Password must be at least 8 characters.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	user := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.db.CreateUser(r.Context(), user); err != nil {
		reRender("Could not create the account (username or email may be taken).")
		return
	}

	if _, err := s.sessions.Issue(w, r, user.ID); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// safeNext returns next only if it is a safe local path (prevents open redirect).
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return ""
	}
	return next
}
