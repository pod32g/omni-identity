package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

type ctxKey int

const (
	userCtxKey ctxKey = iota
	sessCtxKey
)

// requireAdmin wraps a handler so only authenticated admin users may reach it.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.sessions.Current(r)
		if err != nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		user, err := s.db.GetUserByID(r.Context(), sess.UserID)
		if err != nil || !user.IsAdmin || user.Disabled {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, user)))
	}
}

func currentUser(r *http.Request) *model.User {
	u, _ := r.Context().Value(userCtxKey).(*model.User)
	return u
}

// csrfOK validates the form CSRF token for admin POSTs.
func (s *Server) csrfOK(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- users ---

type adminUsersPage struct {
	CSRFToken      string
	Me             *model.User
	Active         string
	Users          []model.User
	Error          string
	SetupLink      string // one-time activation/reset link, shown once
	SetupLinkLabel string
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, status, "admin_users", adminUsersPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "users",
		Users:     users,
		Error:     errMsg,
	})
}

// renderUsersWithLink renders the users page with a one-time link banner.
func (s *Server) renderUsersWithLink(w http.ResponseWriter, r *http.Request, link, label string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, http.StatusOK, "admin_users", adminUsersPage{
		CSRFToken:      auth.CSRFToken(w, r, s.cookieSecure()),
		Me:             currentUser(r),
		Active:         "users",
		Users:          users,
		SetupLink:      link,
		SetupLinkLabel: label,
	})
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, "")
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	isAdmin := r.PostFormValue("is_admin") == "on" || r.PostFormValue("is_admin") == "true"

	if username == "" || email == "" {
		s.renderUsers(w, r, http.StatusBadRequest, "Username and email are required.")
		return
	}

	// Invite mode: create the account with no usable password and hand the admin
	// a one-time setup link for the user to choose their own password.
	invite := r.PostFormValue("invite") == "on" || r.PostFormValue("invite") == "true"

	var hash string
	if invite {
		hash = "" // empty hash never verifies → password login disabled until set
	} else {
		if msg := auth.ValidatePassword(password, username, email, s.passwordPolicy()); msg != "" {
			s.renderUsers(w, r, http.StatusBadRequest, msg)
			return
		}
		h, err := auth.HashPassword(password)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		hash = h
	}

	now := time.Now().UTC()
	u := &model.User{
		ID: uuid.NewString(), Username: username, Email: email,
		PasswordHash: hash, IsAdmin: isAdmin, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.db.CreateUser(r.Context(), u); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not create user (username or email may be taken).")
		return
	}

	if invite {
		link, err := s.issuePasswordToken(r.Context(), u.ID, model.PasswordTokenActivation, activationTokenTTL)
		if err != nil {
			s.renderUsers(w, r, http.StatusInternalServerError, "User created, but the setup link could not be generated.")
			return
		}
		s.audit(r, evtUserInvited, auditEntry{actorUserID: actorID(r), username: username, success: true})
		s.renderUsersWithLink(w, r, link, "Setup link for "+username+" (valid 72 hours, single use):")
		return
	}

	s.audit(r, evtUserCreated, auditEntry{actorUserID: actorID(r), username: username, success: true, detail: "admin=" + boolStr(isAdmin)})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (s *Server) handleAdminToggleUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	// Guard against locking yourself out.
	if me := currentUser(r); me != nil && me.ID == id {
		s.renderUsers(w, r, http.StatusBadRequest, "You cannot disable your own account.")
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	if err := s.db.SetUserDisabled(r.Context(), id, disabled); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not update user.")
		return
	}
	if disabled {
		// Revoke active sessions for a disabled account immediately.
		_, _ = s.db.DeleteSessionsForUser(r.Context(), id, "")
	}
	s.audit(r, evtUserDisabled, auditEntry{actorUserID: actorID(r), success: true, detail: "id=" + id + " disabled=" + boolStr(disabled)})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	password := r.PostFormValue("password")
	if msg := auth.ValidatePassword(password, "", "", s.passwordPolicy()); msg != "" {
		s.renderUsers(w, r, http.StatusBadRequest, msg)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.db.SetUserPassword(r.Context(), id, hash); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not change password.")
		return
	}
	// Force re-auth elsewhere by clearing the target's other sessions.
	_, _ = s.db.DeleteSessionsForUser(r.Context(), id, "")
	s.audit(r, evtPasswordChange, auditEntry{actorUserID: actorID(r), success: true, detail: "admin set password for id=" + id})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- settings ---

type adminSettingsPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Settings  SettingsView // editable, applied live
	Host      string       // read-only infra (boot-bound)
	Port      int
	DBDriver  string
	LDAP      ldapStatusView // read-only directory status (config/env bound)
	Branding  *model.Branding
	HasLogo   bool
	Error     string
	Saved     string
}

// ldapStatusView is the read-only directory summary shown on the settings page.
// It deliberately omits the bind password and other secrets — those live in
// config/env only and are never rendered.
type ldapStatusView struct {
	Enabled      bool
	Preset       string
	URL          string
	StartTLS     bool
	BaseDN       string
	AdminGroupDN string
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, "", "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, errMsg, saved string) {
	b, _ := s.db.GetBranding(r.Context())
	if b == nil {
		b = &model.Branding{ProductName: "Omni Identity"}
	}
	s.tmpl.render(w, status, "admin_settings", adminSettingsPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "settings",
		Settings:  s.settings.Current(),
		Host:      s.cfg.Server.Host,
		Port:      s.cfg.Server.Port,
		DBDriver:  s.cfg.Database.Driver,
		LDAP: ldapStatusView{
			Enabled:      s.cfg.LDAP.Enabled,
			Preset:       s.cfg.LDAP.Preset,
			URL:          s.cfg.LDAP.URL,
			StartTLS:     s.cfg.LDAP.StartTLS,
			BaseDN:       s.cfg.LDAP.BaseDN,
			AdminGroupDN: s.cfg.LDAP.AdminGroupDN,
		},
		Branding: b,
		HasLogo:   len(b.LogoBytes) > 0,
		Error:     errMsg,
		Saved:     saved,
	})
}
