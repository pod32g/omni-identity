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

const userCtxKey ctxKey = iota

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
	CSRFToken string
	Me        *model.User
	Active    string
	Users     []model.User
	Error     string
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, status, "admin_users", adminUsersPage{
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:        currentUser(r),
		Active:    "users",
		Users:     users,
		Error:     errMsg,
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
	if len(password) < 8 {
		s.renderUsers(w, r, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
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
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	password := r.PostFormValue("password")
	if len(password) < 8 {
		s.renderUsers(w, r, http.StatusBadRequest, "Password must be at least 8 characters.")
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
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- settings ---

type adminSettingsPage struct {
	CSRFToken  string
	Me         *model.User
	Active     string
	Issuer     string
	PublicURL  string
	TokenTTL   string
	RefreshTTL string
	Branding   *model.Branding
	HasLogo    bool
	Error      string
	Saved      string
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
		CSRFToken:  auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:         currentUser(r),
		Active:     "settings",
		Issuer:     s.cfg.Security.Issuer,
		PublicURL:  s.cfg.Server.PublicURL,
		TokenTTL:   s.cfg.Security.TokenTTL.String(),
		RefreshTTL: s.cfg.Security.RefreshTokenTTL.String(),
		Branding:   b,
		HasLogo:    len(b.LogoBytes) > 0,
		Error:      errMsg,
		Saved:      saved,
	})
}
