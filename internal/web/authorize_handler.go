package web

import (
	"net/http"
	"net/url"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
)

const authCodeTTL = 5 * time.Minute

// handleAuthorize implements the OAuth2 authorization-code + PKCE endpoint.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Validate the client and redirect_uri BEFORE trusting the redirect target.
	client, err := s.db.GetClient(r.Context(), q.Get("client_id"))
	if err != nil || client.Disabled {
		s.renderError(w, http.StatusBadRequest, "Unknown or disabled client.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !redirectURIAllowed(client, redirectURI) {
		s.renderError(w, http.StatusBadRequest, "Invalid redirect_uri for this client.")
		return
	}

	// From here, parameter errors are reported back to the client via redirect.
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		redirectErr(w, r, redirectURI, "unsupported_response_type", "only response_type=code is supported", state)
		return
	}

	scope := q.Get("scope")
	if !oidc.HasScope(scope, oidc.ScopeOpenID) {
		redirectErr(w, r, redirectURI, "invalid_scope", "the openid scope is required", state)
		return
	}
	if !oidc.ScopesSubset(oidc.SplitScope(scope), client.AllowedScopes) {
		redirectErr(w, r, redirectURI, "invalid_scope", "requested scope is not allowed for this client", state)
		return
	}

	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if client.IsPublic() && challenge == "" {
		redirectErr(w, r, redirectURI, "invalid_request", "PKCE code_challenge is required for public clients", state)
		return
	}
	if challenge != "" && method != oidc.PKCEMethodS256 {
		redirectErr(w, r, redirectURI, "invalid_request", "only the S256 code_challenge_method is supported", state)
		return
	}

	// Require an authenticated browser session; otherwise bounce to login.
	sess, err := s.sessions.Current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}

	// V1 auto-approves first-party consent and issues an authorization code.
	rawCode := auth.RandomToken(32)
	now := time.Now().UTC()
	code := &model.AuthorizationCode{
		CodeHash:            auth.HashToken(rawCode),
		ClientID:            client.ClientID,
		UserID:              sess.UserID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               q.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           now.Add(authCodeTTL),
		CreatedAt:           now,
		AuthTime:            sess.CreatedAt, // when the user actually logged in
	}
	if err := s.db.CreateAuthCode(r.Context(), code); err != nil {
		redirectErr(w, r, redirectURI, "server_error", "could not issue authorization code", state)
		return
	}

	u, _ := url.Parse(redirectURI)
	rq := u.Query()
	rq.Set("code", rawCode)
	if state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func redirectURIAllowed(c *model.Client, uri string) bool {
	if uri == "" {
		return false
	}
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
