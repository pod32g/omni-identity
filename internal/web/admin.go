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

// --- dashboard ---

type adminDashboardPage struct {
	CSRFToken string
	Me        *model.User
	Active    string

	UserCount     int
	UserDisabled  int
	ClientCount   int
	ClientDisable int
	MFAPercent    int
	MFAEnabled    int
	MFAEligible   int
	FailedLogins  int // failed logins in the last 24h (within the recent window)

	Recent []auditView
	Nudges []dashNudge
}

// dashNudge is a one-line setup hint shown on the dashboard when something
// noteworthy needs the admin's attention.
type dashNudge struct {
	Text string
	Href string
	Link string // link label appended after Text, optional
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, _ := s.db.ListUsers(ctx)
	clients, _ := s.db.ListClients(ctx)
	events, _ := s.db.ListAuditEvents(ctx, 200)

	page := adminDashboardPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "home",
	}

	page.UserCount = len(users)
	for i := range users {
		u := &users[i]
		if u.Disabled {
			page.UserDisabled++
		}
		if u.IsLocal() {
			page.MFAEligible++
			if u.MFAEnabled {
				page.MFAEnabled++
			}
		}
	}
	if page.MFAEligible > 0 {
		page.MFAPercent = page.MFAEnabled * 100 / page.MFAEligible
	}

	page.ClientCount = len(clients)
	for i := range clients {
		if clients[i].Disabled {
			page.ClientDisable++
		}
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	page.Recent = make([]auditView, 0, 8)
	for _, e := range events {
		if e.Event == evtLoginFailed && e.CreatedAt.After(cutoff) {
			page.FailedLogins++
		}
		if len(page.Recent) < 8 {
			page.Recent = append(page.Recent, auditView{
				Time:     e.CreatedAt.Format("Jan 2, 15:04"),
				Event:    e.Event,
				Username: e.Username,
				ClientID: e.ClientID,
				IP:       e.IP,
				Success:  e.Success,
				Detail:   e.Detail,
			})
		}
	}

	// Setup nudges: only surfaced when relevant.
	if page.ClientCount == 0 {
		page.Nudges = append(page.Nudges, dashNudge{
			Text: "No applications are registered yet. ", Href: "/admin/clients", Link: "Register your first app",
		})
	}
	if !s.settings.Current().CookieSecure {
		page.Nudges = append(page.Nudges, dashNudge{
			Text: "Secure cookies are off — turn them on once you're serving over HTTPS. ", Href: "/admin/settings", Link: "Review settings",
		})
	}

	s.tmpl.render(w, http.StatusOK, "admin_dashboard", page)
}

// --- users ---

type adminUsersPage struct {
	CSRFToken        string
	Me               *model.User
	Active           string
	Users            []model.User
	Error            string
	Warning          string // non-fatal advisory (e.g. directory user created without a password)
	SetupLink        string // one-time activation/reset link, shown once
	SetupLinkLabel   string
	DirectoryEnabled bool // a managed directory is configured (offer directory create)
}

// renderUsersWithWarning renders the users page with a non-fatal advisory banner.
func (s *Server) renderUsersWithWarning(w http.ResponseWriter, r *http.Request, warning string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, http.StatusOK, "admin_users", adminUsersPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		Users:            users,
		Warning:          warning,
		DirectoryEnabled: s.directoryEnabled(),
	})
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, status, "admin_users", adminUsersPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		Users:            users,
		Error:            errMsg,
		DirectoryEnabled: s.directoryEnabled(),
	})
}

// renderUsersWithLink renders the users page with a one-time link banner.
func (s *Server) renderUsersWithLink(w http.ResponseWriter, r *http.Request, link, label string) {
	users, _ := s.db.ListUsers(r.Context())
	s.tmpl.render(w, http.StatusOK, "admin_users", adminUsersPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		Users:            users,
		SetupLink:        link,
		SetupLinkLabel:   label,
		DirectoryEnabled: s.directoryEnabled(),
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

	// Directory source: provision the user in the canonical directory instead of
	// the local store. admin-ness for directory users comes from the directory's
	// groups, so is_admin is ignored on this path.
	if src := r.PostFormValue("source"); src == "ldap" || src == "directory" {
		s.handleAdminCreateDirectoryUser(w, r, username, email, strings.TrimSpace(r.PostFormValue("display_name")), password)
		return
	}

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
		s.userActionError(w, r, http.StatusBadRequest, "You cannot disable your own account.")
		return
	}
	disabled := r.PostFormValue("disabled") == "true"
	if err := s.db.SetUserDisabled(r.Context(), id, disabled); err != nil {
		s.userActionError(w, r, http.StatusBadRequest, "Could not update user.")
		return
	}
	if disabled {
		// Revoke active sessions for a disabled account immediately.
		_, _ = s.db.DeleteSessionsForUser(r.Context(), id, "")
	}
	s.audit(r, evtUserDisabled, auditEntry{actorUserID: actorID(r), success: true, detail: "id=" + id + " disabled=" + boolStr(disabled)})
	s.userActionDone(w, r, id)
}

func (s *Server) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	password := r.PostFormValue("password")
	user, err := s.db.GetUserByID(r.Context(), id)
	if err != nil || user == nil {
		s.userActionError(w, r, http.StatusNotFound, "User not found.")
		return
	}
	if msg := auth.ValidatePassword(password, user.Username, user.Email, s.passwordPolicy()); msg != "" {
		s.userActionError(w, r, http.StatusBadRequest, msg)
		return
	}

	// Directory users: set the password in the canonical directory, not the local
	// store (their local hash is never consulted at login).
	if !user.IsLocal() {
		dir := s.directoryManager()
		if dir == nil {
			s.userActionError(w, r, http.StatusBadRequest, "This account is managed by an external directory; passwords can't be set here.")
			return
		}
		if err := dir.SetPassword(r.Context(), user.ExternalID, password); err != nil {
			s.userActionError(w, r, http.StatusBadGateway, "The directory rejected the password change.")
			return
		}
		_, _ = s.db.DeleteSessionsForUser(r.Context(), id, "")
		s.audit(r, evtDirPasswordSet, auditEntry{actorUserID: actorID(r), username: user.Username, success: true, detail: "dn=" + user.ExternalID})
		s.userActionDone(w, r, id)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.db.SetUserPassword(r.Context(), id, hash); err != nil {
		s.userActionError(w, r, http.StatusBadRequest, "Could not change password.")
		return
	}
	// Force re-auth elsewhere by clearing the target's other sessions.
	_, _ = s.db.DeleteSessionsForUser(r.Context(), id, "")
	s.audit(r, evtPasswordChange, auditEntry{actorUserID: actorID(r), success: true, detail: "admin set password for id=" + id})
	s.userActionDone(w, r, id)
}

// --- user detail ---

type adminUserDetailPage struct {
	CSRFToken        string
	Me               *model.User
	Active           string
	User             *model.User
	Error            string
	Warning          string // non-fatal advisory (e.g. promoted with no directory password)
	SetupLink        string // one-time reset link, shown once
	SetupLinkLabel   string
	DirectoryEnabled bool // a managed directory is configured (offer directory edit/delete)
}

// renderUserDetailWithWarning renders the user page with a non-fatal advisory.
func (s *Server) renderUserDetailWithWarning(w http.ResponseWriter, r *http.Request, u *model.User, warning string) {
	s.tmpl.render(w, http.StatusOK, "admin_user_detail", adminUserDetailPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		User:             u,
		Warning:          warning,
		DirectoryEnabled: s.directoryEnabled(),
	})
}

func (s *Server) renderUserDetail(w http.ResponseWriter, r *http.Request, status int, u *model.User, errMsg string) {
	s.tmpl.render(w, status, "admin_user_detail", adminUserDetailPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		User:             u,
		Error:            errMsg,
		DirectoryEnabled: s.directoryEnabled(),
	})
}

func (s *Server) renderUserDetailWithLink(w http.ResponseWriter, r *http.Request, u *model.User, link, label string) {
	s.tmpl.render(w, http.StatusOK, "admin_user_detail", adminUserDetailPage{
		CSRFToken:        auth.CSRFToken(w, r, s.cookieSecure()),
		Me:               currentUser(r),
		Active:           "users",
		User:             u,
		SetupLink:        link,
		SetupLinkLabel:   label,
		DirectoryEnabled: s.directoryEnabled(),
	})
}

func (s *Server) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	u, err := s.db.GetUserByID(r.Context(), r.PathValue("id"))
	if err != nil || u == nil {
		s.renderError(w, http.StatusNotFound, "User not found.")
		return
	}
	s.renderUserDetail(w, r, http.StatusOK, u, "")
}

// fromDetail reports whether a per-user action POST originated from the detail
// page (vs. the list), so success/error rendering can return to the right page.
func fromDetail(r *http.Request) bool { return r.PostFormValue("return") == "detail" }

// userActionDone redirects back to the page a per-user action came from.
func (s *Server) userActionDone(w http.ResponseWriter, r *http.Request, id string) {
	if fromDetail(r) {
		http.Redirect(w, r, "/admin/users/"+id, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// userActionError re-renders the originating page (detail or list) with an error.
func (s *Server) userActionError(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	if fromDetail(r) {
		if u, err := s.db.GetUserByID(r.Context(), r.PathValue("id")); err == nil && u != nil {
			s.renderUserDetail(w, r, status, u, errMsg)
			return
		}
	}
	s.renderUsers(w, r, status, errMsg)
}

// --- settings ---

type adminSettingsPage struct {
	CSRFToken            string
	Me                   *model.User
	Active               string
	Settings             SettingsView // editable, applied live
	Host                 string       // read-only infra (boot-bound)
	Port                 int
	DBDriver             string
	AllowInsecureHTTP    bool
	MetricsEnabled       bool
	SetupTokenConfigured bool
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	MaxHeaderBytes       int
	LogoMaxKiB           int
	LDAP                 ldapStatusView // read-only directory status (config/env bound)
	Branding             *model.Branding
	HasLogo              bool
	Error                string
	Saved                string
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
	WriteCapable bool // a privileged bind is configured, so management can be toggled on
	Manageable   bool // write management is currently enabled (write-capable AND toggled on)
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
		CSRFToken:            auth.CSRFToken(w, r, s.cookieSecure()),
		Me:                   currentUser(r),
		Active:               "settings",
		Settings:             s.settings.Current(),
		Host:                 s.cfg.Server.Host,
		Port:                 s.cfg.Server.Port,
		DBDriver:             s.cfg.Database.Driver,
		AllowInsecureHTTP:    s.cfg.Server.AllowInsecureHTTP,
		MetricsEnabled:       strings.TrimSpace(s.cfg.Metrics.BearerToken) != "",
		SetupTokenConfigured: strings.TrimSpace(s.cfg.Security.SetupToken) != "",
		ReadHeaderTimeout:    s.cfg.Server.ReadHeaderTimeout,
		ReadTimeout:          s.cfg.Server.ReadTimeout,
		WriteTimeout:         s.cfg.Server.WriteTimeout,
		IdleTimeout:          s.cfg.Server.IdleTimeout,
		MaxHeaderBytes:       s.cfg.Server.MaxHeaderBytes,
		LogoMaxKiB:           max(1, s.settings.Current().MaxLogoBytes/1024),
		LDAP: ldapStatusView{
			Enabled:      s.cfg.LDAP.Enabled,
			Preset:       s.cfg.LDAP.Preset,
			URL:          s.cfg.LDAP.URL,
			StartTLS:     s.cfg.LDAP.StartTLS,
			BaseDN:       s.cfg.LDAP.BaseDN,
			AdminGroupDN: s.cfg.LDAP.AdminGroupDN,
			WriteCapable: s.directoryWriteCapable(),
			Manageable:   s.directoryEnabled(),
		},
		Branding: b,
		HasLogo:  len(b.LogoBytes) > 0,
		Error:    errMsg,
		Saved:    saved,
	})
}
