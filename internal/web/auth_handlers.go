package web

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

type loginPage struct {
	CSRFToken string
	Error     string
	Next      string   // same-origin path for plain admin login
	Req       string   // parked OIDC auth-request id, when arriving from /oauth2/authorize
	App       *appView // requesting application, nil for admin login
}

// appView is the requesting application's display info shown on the hosted
// login and consent pages.
type appView struct {
	Name     string
	LogoURL  string
	Domain   string
	Homepage string
}

// appViewFor builds the display info for a client + redirect target.
func appViewFor(c *model.Client, redirectURI string) *appView {
	return &appView{
		Name:     c.Label(),
		LogoURL:  c.LogoURL,
		Domain:   appDomain(redirectURI),
		Homepage: c.HomepageURL,
	}
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

	reqID := r.URL.Query().Get("req")
	var app *appView
	if reqID != "" {
		p, _, ok := s.loadAuthRequest(w, r, reqID)
		if !ok {
			return // loadAuthRequest rendered the error page
		}
		// Already signed in? Skip the login page and continue automatically.
		if sess, err := s.sessions.Current(r); err == nil {
			s.continueAfterAuth(w, r, p, reqID, sess.UserID, sess.CreatedAt)
			return
		}
		app = appViewFor(p.client, p.redirectURI)
	}

	s.renderLogin(w, r, http.StatusOK, "", reqID, safeNext(r.URL.Query().Get("next")), app)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, errMsg, reqID, next string, app *appView) {
	s.tmpl.render(w, status, "login", loginPage{
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Error:     errMsg,
		Next:      next,
		Req:       reqID,
		App:       app,
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

	reqID := r.PostFormValue("req")
	next := safeNext(r.PostFormValue("next"))
	username := r.PostFormValue("username")

	// Re-resolve the requesting app for re-rendering on failure.
	var app *appView
	var p authzParams
	var haveReq bool
	if reqID != "" {
		var ok bool
		p, _, ok = s.loadAuthRequest(w, r, reqID)
		if !ok {
			return
		}
		app = appViewFor(p.client, p.redirectURI)
		haveReq = true
	}

	password := r.PostFormValue("password")
	now := time.Now().UTC()

	// Rate-limit by client IP + submitted username to blunt credential stuffing.
	rlKey := clientIP(r) + "|" + username
	if !s.loginRate.Allowed(rlKey) {
		s.renderLogin(w, r, http.StatusTooManyRequests,
			"Too many sign-in attempts. Please wait a few minutes and try again.",
			reqID, next, app)
		return
	}

	invalid := func() {
		s.loginRate.Fail(rlKey)
		s.renderLogin(w, r, http.StatusUnauthorized, "Invalid username or password.", reqID, next, app)
	}

	user, err := s.db.GetUserByUsername(r.Context(), username)
	if err != nil {
		auth.DummyVerify(password) // equalize timing for unknown users
		s.audit(r, evtLoginFailed, auditEntry{username: username, detail: "unknown user"})
		invalid()
		return
	}

	// Account lockout: refuse before checking the password.
	if user.IsLocked(now) {
		s.audit(r, evtLoginLocked, auditEntry{actorUserID: user.ID, username: username, detail: "attempt while locked"})
		s.renderLogin(w, r, http.StatusTooManyRequests,
			"Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.",
			reqID, next, app)
		return
	}

	ok, _ := auth.VerifyPassword(password, user.PasswordHash)
	if !ok || user.Disabled {
		if !user.Disabled {
			count, _ := s.db.RecordFailedLogin(r.Context(), user.ID,
				s.cfg.Security.MaxFailedLogins, now.Add(s.cfg.Security.LockoutDuration))
			if count >= s.cfg.Security.MaxFailedLogins {
				s.audit(r, evtLoginLocked, auditEntry{actorUserID: user.ID, username: username, detail: "locked after failed attempts"})
			} else {
				s.audit(r, evtLoginFailed, auditEntry{actorUserID: user.ID, username: username, detail: "bad password"})
			}
		} else {
			s.audit(r, evtLoginFailed, auditEntry{actorUserID: user.ID, username: username, detail: "disabled account"})
		}
		invalid()
		return
	}

	// Password correct: clear failure state.
	_ = s.db.ResetFailedLogins(r.Context(), user.ID)
	s.loginRate.Reset(rlKey)

	// Second factor required? Park a challenge and divert to the MFA step.
	if user.MFAEnabled {
		s.startMFAChallenge(w, r, user, next, reqID)
		return
	}

	// Rotates the session id (fixation guard) on success.
	if _, err := s.sessions.Issue(w, r, user.ID, "pwd"); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	s.audit(r, evtLoginSuccess, auditEntry{actorUserID: user.ID, username: username, success: true})

	if haveReq {
		s.continueAfterAuth(w, r, p, reqID, user.ID, now)
		return
	}

	dest := next
	if dest == "" {
		dest = redirectAfterLogin(user)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// redirectAfterLogin sends admins to the console and everyone else to their
// self-service account page.
func redirectAfterLogin(u *model.User) string {
	if u.IsAdmin {
		return "/admin"
	}
	return "/account"
}

// continueAfterAuth resumes a parked authorization request once the user is
// authenticated: trusted clients get a code immediately; others are sent to the
// consent screen.
func (s *Server) continueAfterAuth(w http.ResponseWriter, r *http.Request, p authzParams, reqID, userID string, authTime time.Time) {
	if p.client.SkipConsent {
		_ = s.db.DeleteAuthRequest(r.Context(), reqID)
		s.issueCode(w, r, p, userID, authTime)
		return
	}
	http.Redirect(w, r, "/consent?req="+url.QueryEscape(reqID), http.StatusSeeOther)
}

// clientIP returns the remote IP for rate-limit keying, preferring the host
// portion of RemoteAddr.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleLogout is the CSRF-protected POST used by the admin nav button. It
// clears the session and shows the branded signed-out page.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	var actor string
	if sess, err := s.sessions.Current(r); err == nil {
		actor = sess.UserID
	}
	if err := s.sessions.Destroy(w, r); err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	s.audit(r, evtLogout, auditEntry{actorUserID: actor, success: true})
	s.renderSignedOut(w, r, "")
}

// renderSignedOut shows the hosted "you've signed out" page. continueURL, when
// non-empty, is offered as a link back to the application.
func (s *Server) renderSignedOut(w http.ResponseWriter, r *http.Request, continueURL string) {
	s.tmpl.render(w, http.StatusOK, "logout", map[string]any{
		"ContinueURL": continueURL,
	})
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
	if msg := auth.ValidatePassword(password, username, email, s.cfg.Security.PasswordMinLength); msg != "" {
		reRender(msg)
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

	if _, err := s.sessions.Issue(w, r, user.ID, "pwd"); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	s.audit(r, evtLoginSuccess, auditEntry{actorUserID: user.ID, username: username, success: true, detail: "first-run admin"})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// safeNext returns next only if it is a safe, local, same-origin path. It
// guards against open redirects, including the backslash and control-character
// bypasses that browsers normalize into protocol-relative URLs.
func safeNext(next string) string {
	if next == "" {
		return ""
	}
	for _, r := range next {
		if r == '\\' || r < 0x20 || r == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" ||
		!strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return ""
	}
	return next
}
