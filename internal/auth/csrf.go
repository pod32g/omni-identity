package auth

import (
	"crypto/subtle"
	"net/http"

	"github.com/pod32g/omni-identity/internal/model"
)

const csrfCookieName = "omni_csrf"

// CSRFToken returns the CSRF token for this request, setting a fresh double-submit
// cookie if one is not already present. Render the returned value as a hidden
// form field; validate it on POST with ValidateCSRFToken.
func CSRFToken(w http.ResponseWriter, r *http.Request, secure bool) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	tok := RandomToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// ValidateCSRFToken reports whether the submitted token matches the
// double-submit cookie, using a constant-time comparison.
func ValidateCSRFToken(r *http.Request, submitted string) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" || submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(submitted)) == 1
}

// ValidateSessionCSRF reports whether submitted matches the session's CSRF
// secret (used for authenticated forms once a session exists).
func ValidateSessionCSRF(sess *model.Session, submitted string) bool {
	if sess == nil || sess.CSRFSecret == "" || submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sess.CSRFSecret), []byte(submitted)) == 1
}
