package web

import (
	"context"
	"crypto/subtle"
	"log/slog"
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
	CSRFToken     string
	Error         string
	Notice        string   // success flash (e.g. after setting a password)
	Next          string   // same-origin path for plain admin login
	Req           string   // parked OIDC auth-request id, when arriving from /oauth2/authorize
	App           *appView // requesting application, nil for admin login
	ForgotEnabled bool     // show the self-service "Forgot password?" link
}

// loginNotices maps known notice codes to user-facing messages (no free text,
// so nothing attacker-controlled is rendered).
var loginNotices = map[string]string{
	"password-set": "Your password has been set. Please sign in.",
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
	CSRFToken     string
	Error         string
	Username      string
	Email         string
	TokenRequired bool
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

	// Already signed in: never show an "expired link" error. Continue the OAuth
	// request when it's still valid (the common "skip the login page" case);
	// otherwise the one-time request was already spent (double-submit, Back, or a
	// client re-init), so send them to their landing page instead of a 400.
	if sess, err := s.sessions.Current(r); err == nil {
		if reqID != "" {
			if p, _, ok := s.peekAuthRequest(r.Context(), reqID); ok {
				s.continueAfterAuth(w, r, p, reqID, sess.UserID, sess.CreatedAt)
				return
			}
		}
		http.Redirect(w, r, s.signedInLanding(r.Context(), sess.UserID), http.StatusSeeOther)
		return
	}

	// Not signed in: a parked request must be valid to render the SSO context.
	var app *appView
	if reqID != "" {
		p, _, ok := s.loadAuthRequest(w, r, reqID)
		if !ok {
			return // loadAuthRequest rendered the error page
		}
		app = appViewFor(p.client, p.redirectURI)
	}

	s.renderLogin(w, r, http.StatusOK, "", reqID, safeNext(r.URL.Query().Get("next")), app)
}

// signedInLanding is where an already-authenticated user is sent when there is no
// live OAuth request to continue.
func (s *Server) signedInLanding(ctx context.Context, userID string) string {
	if u, err := s.db.GetUserByID(ctx, userID); err == nil && u != nil {
		return redirectAfterLogin(u)
	}
	return "/account"
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, errMsg, reqID, next string, app *appView) {
	s.tmpl.render(w, status, "login", loginPage{
		CSRFToken:     auth.CSRFToken(w, r, s.cookieSecure()),
		Error:         errMsg,
		Notice:        loginNotices[r.URL.Query().Get("notice")],
		Next:          next,
		Req:           reqID,
		App:           app,
		ForgotEnabled: s.forgotEnabled(),
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
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	ipKey := clientIP(r)
	policy := s.settings.Current()

	if !s.loginIPRate.Allowed(ipKey, policy.LoginIPMaxAttempts, policy.RateLimitWindow) {
		s.renderLogin(w, r, http.StatusTooManyRequests,
			"Too many sign-in attempts. Please wait a few minutes and try again.",
			reqID, next, nil)
		return
	}

	// Re-resolve the requesting app for re-rendering on failure.
	var app *appView
	var p authzParams
	var haveReq bool
	if reqID != "" {
		var ok bool
		p, _, ok = s.peekAuthRequest(r.Context(), reqID)
		if !ok {
			// The one-time request is gone (double-submit, Back, or expiry). If the
			// user is already signed in — e.g. a first submit just succeeded and
			// consumed it — finish gracefully instead of a confusing "expired"
			// error; otherwise render the genuine expiry.
			if sess, serr := s.sessions.Current(r); serr == nil {
				http.Redirect(w, r, s.signedInLanding(r.Context(), sess.UserID), http.StatusSeeOther)
				return
			}
			s.loadAuthRequest(w, r, reqID) // renders the proper expiry error
			return
		}
		app = appViewFor(p.client, p.redirectURI)
		haveReq = true
	}

	now := time.Now().UTC()

	// Rate-limit by client IP + submitted username to blunt credential stuffing.
	rlKey := ipKey + "|" + username
	if !s.loginRate.Allowed(rlKey, policy.MaxFailedLogins, policy.RateLimitWindow) {
		s.renderLogin(w, r, http.StatusTooManyRequests,
			"Too many sign-in attempts. Please wait a few minutes and try again.",
			reqID, next, app)
		return
	}

	invalid := func() {
		s.loginIPRate.Fail(ipKey, policy.RateLimitWindow)
		s.loginRate.Fail(rlKey, policy.RateLimitWindow)
		s.renderLogin(w, r, http.StatusUnauthorized, "Invalid username or password.", reqID, next, app)
	}

	if len(username) > policy.MaxLoginUsernameBytes || len(password) > policy.MaxLoginPasswordBytes {
		invalid()
		return
	}

	// Resolve the credential against the local password store first; fall back to
	// external connectors (e.g. LDAP) for unknown or directory-sourced users.
	user, lookupErr := s.db.GetUserByUsername(r.Context(), username)
	switch {
	case lookupErr == nil && user.IsLocal():
		// Account lockout: refuse before checking the password.
		if user.IsLocked(now) {
			s.metrics.recordLogin("local", "failure")
			s.audit(r, evtLoginLocked, auditEntry{actorUserID: user.ID, username: username, detail: "attempt while locked"})
			s.renderLogin(w, r, http.StatusTooManyRequests,
				"Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.",
				reqID, next, app)
			return
		}

		release, acquired := s.acquirePasswordVerify()
		if !acquired {
			s.renderLogin(w, r, http.StatusTooManyRequests,
				"Too many sign-in attempts. Please wait a few minutes and try again.",
				reqID, next, app)
			return
		}
		ok, _ := auth.VerifyPassword(password, user.PasswordHash)
		release()
		if !ok || user.Disabled {
			if !user.Disabled {
				sv := s.settings.Current()
				count, _ := s.db.RecordFailedLogin(r.Context(), user.ID,
					sv.MaxFailedLogins, now.Add(sv.LockoutDuration))
				if count >= sv.MaxFailedLogins {
					s.audit(r, evtLoginLocked, auditEntry{actorUserID: user.ID, username: username, detail: "locked after failed attempts"})
				} else {
					s.audit(r, evtLoginFailed, auditEntry{actorUserID: user.ID, username: username, detail: "bad password"})
				}
			} else {
				s.audit(r, evtLoginFailed, auditEntry{actorUserID: user.ID, username: username, detail: "disabled account"})
			}
			s.metrics.recordLogin("local", "failure")
			invalid()
			return
		}
		_ = s.db.ResetFailedLogins(r.Context(), user.ID)
		s.metrics.recordLogin("local", "success")

	case len(s.connectors) > 0:
		// Directory-sourced or unknown-local accounts are verified by external
		// connectors and just-in-time provisioned into a local mirror account.
		authed, ok := s.authViaConnectors(r, username, password)
		if !ok {
			s.metrics.recordLogin("ldap", "failure")
			s.audit(r, evtLoginFailed, auditEntry{username: username, detail: "external: invalid"})
			invalid()
			return
		}
		if authed.Disabled {
			s.metrics.recordLogin(authed.AuthSource, "failure")
			s.audit(r, evtLoginFailed, auditEntry{actorUserID: authed.ID, username: username, detail: "disabled account"})
			invalid()
			return
		}
		s.metrics.recordLogin(authed.AuthSource, "success")
		user = authed

	default:
		// Unknown user and no external connectors: bounded dummy Argon2id check to
		// equalize timing without allowing unlimited CPU work.
		release, ok := s.acquirePasswordVerify()
		if !ok {
			s.renderLogin(w, r, http.StatusTooManyRequests,
				"Too many sign-in attempts. Please wait a few minutes and try again.",
				reqID, next, app)
			return
		}
		auth.DummyVerify(password) // equalize timing for unknown users
		release()
		s.audit(r, evtLoginFailed, auditEntry{username: username, detail: "unknown user"})
		s.metrics.recordLogin("unknown", "failure")
		invalid()
		return
	}
	s.loginRate.Reset(rlKey)
	s.loginIPRate.Reset(ipKey)

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

// authViaConnectors verifies the credential against each external connector in
// order and returns the just-in-time-provisioned local user on the first
// success. ok=false means no connector accepted the credentials; transport or
// provisioning errors are logged (operator-visible) and never surfaced to the
// browser, so they read as a generic invalid login.
func (s *Server) authViaConnectors(r *http.Request, username, password string) (*model.User, bool) {
	for _, c := range s.connectors {
		id, ok, err := c.Login(r.Context(), username, password)
		if err != nil {
			slog.Error("connector login error", "connector", c.ID(), "username", username, "error", err.Error())
			continue
		}
		if !ok {
			continue
		}
		u, perr := s.db.UpsertExternalUser(r.Context(), id.Connector, id.ExternalID,
			id.Username, id.Email, id.DisplayName, id.IsAdmin)
		if perr != nil {
			slog.Error("connector provision failed", "connector", c.ID(), "username", username, "error", perr.Error())
			return nil, false
		}
		return u, true
	}
	return nil, false
}

func (s *Server) acquirePasswordVerify() (func(), bool) {
	limit := s.settings.Current().PasswordVerifyConcurrency
	if limit < 1 {
		limit = defaultPasswordVerifyConcurrency
	}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if s.verifyActive >= limit {
		return nil, false
	}
	s.verifyActive++
	return func() {
		s.verifyMu.Lock()
		s.verifyActive--
		s.verifyMu.Unlock()
	}, true
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
	token := auth.CSRFToken(w, r, s.cookieSecure())
	s.tmpl.render(w, http.StatusOK, "setup", setupPage{CSRFToken: token, TokenRequired: s.setupTokenRequired()})
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
	if !s.validSetupToken(r.PostFormValue("setup_token")) {
		http.Error(w, "invalid setup token", http.StatusForbidden)
		return
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")

	reRender := func(msg string) {
		token := auth.CSRFToken(w, r, s.cookieSecure())
		s.tmpl.render(w, http.StatusBadRequest, "setup", setupPage{
			CSRFToken: token, Error: msg, Username: username, Email: email, TokenRequired: s.setupTokenRequired(),
		})
	}

	if username == "" || email == "" {
		reRender("Username and email are required.")
		return
	}
	if msg := auth.ValidatePassword(password, username, email, s.passwordPolicy()); msg != "" {
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

func (s *Server) setupTokenRequired() bool {
	if strings.TrimSpace(s.cfg.Security.SetupToken) != "" {
		return true
	}
	u, err := url.Parse(s.settings.Current().PublicURL)
	if err != nil {
		return true
	}
	return !isLoopbackHost(u.Hostname())
}

func (s *Server) validSetupToken(got string) bool {
	want := strings.TrimSpace(s.cfg.Security.SetupToken)
	if want == "" {
		return !s.setupTokenRequired()
	}
	got = strings.TrimSpace(got)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
