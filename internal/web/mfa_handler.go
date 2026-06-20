package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

const mfaCookieName = "omni_mfa"
const mfaChallengeTTL = 5 * time.Minute

type mfaPage struct {
	CSRFToken string
	Error     string
}

// startMFAChallenge parks a second-factor challenge and redirects to the MFA
// step. It does NOT issue a session yet.
func (s *Server) startMFAChallenge(w http.ResponseWriter, r *http.Request, user *model.User, next, reqID string) {
	now := time.Now().UTC()
	ch := &model.LoginChallenge{
		ID:        auth.RandomToken(32),
		UserID:    user.ID,
		Next:      next,
		Req:       reqID,
		CreatedAt: now,
		ExpiresAt: now.Add(mfaChallengeTTL),
	}
	if err := s.db.CreateLoginChallenge(r.Context(), ch); err != nil {
		http.Error(w, "could not start MFA", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    ch.ID,
		Path:     "/login",
		HttpOnly: true,
		Secure:   s.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(mfaChallengeTTL.Seconds()),
	})
	s.audit(r, evtMFAChallenge, auditEntry{actorUserID: user.ID, username: user.Username})
	http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
}

// currentChallenge resolves the pending MFA challenge from the cookie.
func (s *Server) currentChallenge(r *http.Request) *model.LoginChallenge {
	c, err := r.Cookie(mfaCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	ch, err := s.db.GetLoginChallenge(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	return ch
}

func (s *Server) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    "",
		Path:     "/login",
		HttpOnly: true,
		Secure:   s.cfg.Cookies.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) handleMFAForm(w http.ResponseWriter, r *http.Request) {
	if s.currentChallenge(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.tmpl.render(w, http.StatusOK, "mfa", mfaPage{
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
	})
}

func (s *Server) handleMFASubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ch := s.currentChallenge(r)
	if ch == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, err := s.db.GetUserByID(r.Context(), ch.UserID)
	if err != nil || user.Disabled || !user.MFAEnabled {
		s.clearMFACookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rlKey := "mfa|" + user.ID
	if !s.mfaRate.Allowed(rlKey) {
		s.renderMFA(w, r, http.StatusTooManyRequests, "Too many attempts. Please wait and try again.")
		return
	}

	code := strings.TrimSpace(r.PostFormValue("code"))
	if !s.verifySecondFactor(r, user, code) {
		s.mfaRate.Fail(rlKey)
		s.audit(r, evtMFAFailed, auditEntry{actorUserID: user.ID, username: user.Username})
		s.renderMFA(w, r, http.StatusUnauthorized, "Invalid verification code.")
		return
	}
	s.mfaRate.Reset(rlKey)
	_ = s.db.DeleteLoginChallenge(r.Context(), ch.ID)
	s.clearMFACookie(w)

	if _, err := s.sessions.Issue(w, r, user.ID, "pwd mfa"); err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	s.audit(r, evtMFASuccess, auditEntry{actorUserID: user.ID, username: user.Username, success: true})

	if ch.Req != "" {
		p, _, ok := s.loadAuthRequest(w, r, ch.Req)
		if !ok {
			return
		}
		s.continueAfterAuth(w, r, p, ch.Req, user.ID, time.Now().UTC())
		return
	}
	dest := safeNext(ch.Next)
	if dest == "" {
		dest = redirectAfterLogin(user)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// verifySecondFactor accepts either a valid TOTP code or an unused recovery code.
func (s *Server) verifySecondFactor(r *http.Request, user *model.User, code string) bool {
	if code == "" {
		return false
	}
	if secret, err := s.enc.Decrypt(user.TOTPSecret); err == nil {
		if auth.VerifyTOTP(secret, code, time.Now().UTC()) {
			return true
		}
	}
	// Recovery code fallback (single-use, normalized).
	consumed, err := s.db.ConsumeRecoveryCode(r.Context(), user.ID, auth.HashToken(normalizeRecovery(code)))
	return err == nil && consumed
}

func (s *Server) renderMFA(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	s.tmpl.render(w, status, "mfa", mfaPage{
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Error:     errMsg,
	})
}

// normalizeRecovery canonicalizes a recovery code for hashing/comparison.
func normalizeRecovery(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}
