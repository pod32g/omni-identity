package web

import (
	"net/http"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/oidc"
)

type consentPage struct {
	CSRFToken string
	Req       string
	App       *appView
	Scopes    []scopeView
	User      userView
}

type scopeView struct {
	Name        string
	Description string
}

type userView struct {
	Username string
	Email    string
}

// scopeDescriptions maps OIDC scopes to human-readable consent descriptions.
var scopeDescriptions = map[string]string{
	oidc.ScopeOpenID: "Confirm your identity",
	"profile":        "Your profile information (name, username)",
	"email":          "Your email address",
	"offline_access": "Stay signed in (refresh access without re-entering your password)",
}

func describeScopes(scope string) []scopeView {
	var out []scopeView
	for _, s := range oidc.SplitScope(scope) {
		desc := scopeDescriptions[s]
		if desc == "" {
			desc = s
		}
		out = append(out, scopeView{Name: s, Description: desc})
	}
	return out
}

// handleConsentForm shows the consent screen for a parked request. It requires
// an authenticated session; trusted clients never reach here.
func (s *Server) handleConsentForm(w http.ResponseWriter, r *http.Request) {
	reqID := r.URL.Query().Get("req")
	p, _, ok := s.loadAuthRequest(w, r, reqID)
	if !ok {
		return
	}
	sess, err := s.sessions.Current(r)
	if err != nil {
		http.Redirect(w, r, "/login?req="+reqID, http.StatusSeeOther)
		return
	}
	user, err := s.db.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Redirect(w, r, "/login?req="+reqID, http.StatusSeeOther)
		return
	}

	s.tmpl.render(w, http.StatusOK, "consent", consentPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Req:       reqID,
		App:       appViewFor(p.client, p.redirectURI),
		Scopes:    describeScopes(p.scope),
		User:      userView{Username: user.Username, Email: user.Email},
	})
}

// handleConsentSubmit processes Continue/Cancel from the consent screen.
func (s *Server) handleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !auth.ValidateCSRFToken(r, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	reqID := r.PostFormValue("req")
	p, _, ok := s.loadAuthRequest(w, r, reqID)
	if !ok {
		return
	}
	sess, err := s.sessions.Current(r)
	if err != nil {
		http.Redirect(w, r, "/login?req="+reqID, http.StatusSeeOther)
		return
	}

	if r.PostFormValue("action") != "allow" {
		// User cancelled: tell the client per RFC 6749 and drop the request.
		_ = s.db.DeleteAuthRequest(r.Context(), reqID)
		s.audit(r, evtConsentDenied, auditEntry{actorUserID: sess.UserID, clientID: p.client.ClientID})
		redirectErr(w, r, p.redirectURI, "access_denied", "the user denied the request", p.state)
		return
	}

	_ = s.db.DeleteAuthRequest(r.Context(), reqID)
	s.audit(r, evtConsentGranted, auditEntry{actorUserID: sess.UserID, clientID: p.client.ClientID, success: true})
	authTime := sess.CreatedAt
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	s.issueCode(w, r, p, sess.UserID, authTime)
}
