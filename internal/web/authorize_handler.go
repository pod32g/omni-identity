package web

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
)

const (
	authCodeTTL    = 5 * time.Minute
	authRequestTTL = 10 * time.Minute
)

// authzParams holds the validated parameters of an authorization request,
// shared by the direct-issue path and the login/consent resume paths.
type authzParams struct {
	client       *model.Client
	responseType string
	redirectURI  string
	scope        string
	state        string
	nonce        string
	challenge    string
	method       string
}

// handleAuthorize implements the OAuth2 authorization-code + PKCE endpoint. It
// validates the request, then either issues a code immediately (authenticated,
// trusted client) or parks the request and redirects to the hosted login or
// consent page.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := s.validateAuthorize(w, r)
	if !ok {
		return
	}

	q := r.URL.Query()
	prompt := q.Get("prompt")
	sess, sessErr := s.sessions.Current(r)
	authed := sessErr == nil

	// Honor re-authentication requirements: prompt=login or a max_age that the
	// current session's age exceeds forces a fresh login.
	if authed && (prompt == "login" || maxAgeExceeded(q.Get("max_age"), sess.CreatedAt)) {
		authed = false
	}

	if !authed {
		// prompt=none must not show UI; report back to the client per OIDC.
		if prompt == "none" {
			redirectErr(w, r, p.redirectURI, "login_required", "authentication is required but prompt=none was set", p.state)
			return
		}
		s.parkAndRedirect(w, r, p, "/login")
		return
	}

	// Trusted first-party clients skip consent; others get the consent screen.
	if p.client.SkipConsent {
		s.issueCode(w, r, p, sess.UserID, sess.CreatedAt)
		return
	}
	if prompt == "none" {
		redirectErr(w, r, p.redirectURI, "consent_required", "consent is required but prompt=none was set", p.state)
		return
	}
	s.parkAndRedirect(w, r, p, "/consent")
}

// maxAgeExceeded reports whether the session login is older than the requested
// max_age (seconds). A blank or invalid max_age never forces re-auth.
func maxAgeExceeded(maxAge string, authTime time.Time) bool {
	if maxAge == "" {
		return false
	}
	secs, err := strconv.Atoi(maxAge)
	if err != nil || secs < 0 {
		return false
	}
	return time.Since(authTime) > time.Duration(secs)*time.Second
}

// validateAuthorize parses and validates the request. Errors before the
// redirect target is trusted render a branded error page; later errors are
// redirected back to the client per RFC 6749.
func (s *Server) validateAuthorize(w http.ResponseWriter, r *http.Request) (authzParams, bool) {
	q := r.URL.Query()
	p := authzParams{
		responseType: q.Get("response_type"),
		redirectURI:  q.Get("redirect_uri"),
		scope:        q.Get("scope"),
		state:        q.Get("state"),
		nonce:        q.Get("nonce"),
		challenge:    q.Get("code_challenge"),
		method:       q.Get("code_challenge_method"),
	}

	// Validate the client and redirect_uri BEFORE trusting the redirect target.
	client, err := s.db.GetClient(r.Context(), q.Get("client_id"))
	if err != nil || client.Disabled {
		s.renderOIDCError(w, r, http.StatusBadRequest,
			"We don't recognize the application that sent you here.",
			"authorize: unknown or disabled client", "client_id", q.Get("client_id"))
		return p, false
	}
	p.client = client

	if !redirectURIAllowed(client, p.redirectURI) {
		s.renderOIDCError(w, r, http.StatusBadRequest,
			"The application's return address is not registered with Omni Identity.",
			"authorize: redirect_uri not allowed", "client_id", client.ClientID,
			"redirect_uri", p.redirectURI)
		return p, false
	}

	// From here, parameter errors are reported back to the client via redirect.
	if p.responseType != "code" {
		redirectErr(w, r, p.redirectURI, "unsupported_response_type", "only response_type=code is supported", p.state)
		return p, false
	}
	if !oidc.HasScope(p.scope, oidc.ScopeOpenID) {
		redirectErr(w, r, p.redirectURI, "invalid_scope", "the openid scope is required", p.state)
		return p, false
	}
	if !oidc.ScopesSubset(oidc.SplitScope(p.scope), client.AllowedScopes) {
		redirectErr(w, r, p.redirectURI, "invalid_scope", "requested scope is not allowed for this client", p.state)
		return p, false
	}
	if client.IsPublic() && p.challenge == "" {
		redirectErr(w, r, p.redirectURI, "invalid_request", "PKCE code_challenge is required for public clients", p.state)
		return p, false
	}
	if p.challenge != "" && p.method != oidc.PKCEMethodS256 {
		redirectErr(w, r, p.redirectURI, "invalid_request", "only the S256 code_challenge_method is supported", p.state)
		return p, false
	}
	return p, true
}

// parkAndRedirect persists the validated request and redirects the browser to
// dest (the hosted login or consent page) with the request id.
func (s *Server) parkAndRedirect(w http.ResponseWriter, r *http.Request, p authzParams, dest string) {
	now := time.Now().UTC()
	req := &model.AuthRequest{
		ID:                  auth.RandomToken(32),
		ClientID:            p.client.ClientID,
		RedirectURI:         p.redirectURI,
		ResponseType:        p.responseType,
		Scope:               p.scope,
		State:               p.state,
		Nonce:               p.nonce,
		CodeChallenge:       p.challenge,
		CodeChallengeMethod: p.method,
		CreatedAt:           now,
		ExpiresAt:           now.Add(authRequestTTL),
	}
	if err := s.db.CreateAuthRequest(r.Context(), req); err != nil {
		s.renderOIDCError(w, r, http.StatusInternalServerError,
			"We couldn't start the sign-in. Please try again.",
			"authorize: park request", "error", err.Error())
		return
	}
	http.Redirect(w, r, dest+"?req="+url.QueryEscape(req.ID), http.StatusSeeOther)
}

// issueCode mints a single-use authorization code and redirects back to the
// client with code and state.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, p authzParams, userID string, authTime time.Time) {
	rawCode := auth.RandomToken(32)
	now := time.Now().UTC()
	code := &model.AuthorizationCode{
		CodeHash:            auth.HashToken(rawCode),
		ClientID:            p.client.ClientID,
		UserID:              userID,
		RedirectURI:         p.redirectURI,
		Scope:               p.scope,
		Nonce:               p.nonce,
		CodeChallenge:       p.challenge,
		CodeChallengeMethod: p.method,
		ExpiresAt:           now.Add(authCodeTTL),
		CreatedAt:           now,
		AuthTime:            authTime,
	}
	if err := s.db.CreateAuthCode(r.Context(), code); err != nil {
		redirectErr(w, r, p.redirectURI, "server_error", "could not issue authorization code", p.state)
		return
	}

	u, _ := url.Parse(p.redirectURI)
	rq := u.Query()
	rq.Set("code", rawCode)
	if p.state != "" {
		rq.Set("state", p.state)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// loadAuthRequest fetches a parked request and re-resolves its client into
// authzParams. A missing/expired request or vanished client yields ok=false and
// a rendered error page.
func (s *Server) loadAuthRequest(w http.ResponseWriter, r *http.Request, id string) (authzParams, *model.AuthRequest, bool) {
	req, err := s.db.GetAuthRequest(r.Context(), id)
	if err != nil {
		s.renderOIDCError(w, r, http.StatusBadRequest,
			"This sign-in link has expired. Please return to the application and try again.",
			"authrequest: missing or expired", "req", id)
		return authzParams{}, nil, false
	}
	client, err := s.db.GetClient(r.Context(), req.ClientID)
	if err != nil || client.Disabled {
		s.renderOIDCError(w, r, http.StatusBadRequest,
			"We don't recognize the application that sent you here.",
			"authrequest: client gone", "client_id", req.ClientID)
		return authzParams{}, nil, false
	}
	// Defense-in-depth: re-validate the stored redirect against the client's
	// current allowlist, in case it changed while the request was parked.
	if !redirectURIAllowed(client, req.RedirectURI) {
		s.renderOIDCError(w, r, http.StatusBadRequest,
			"The application's return address is no longer registered.",
			"authrequest: redirect_uri no longer allowed",
			"client_id", client.ClientID, "redirect_uri", req.RedirectURI)
		return authzParams{}, nil, false
	}
	p := authzParams{
		client:       client,
		responseType: req.ResponseType,
		redirectURI:  req.RedirectURI,
		scope:        req.Scope,
		state:        req.State,
		nonce:        req.Nonce,
		challenge:    req.CodeChallenge,
		method:       req.CodeChallengeMethod,
	}
	return p, req, true
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

// postLogoutRedirectAllowed reports whether uri exactly matches one of the
// client's registered post-logout redirect URIs.
func postLogoutRedirectAllowed(c *model.Client, uri string) bool {
	if uri == "" {
		return false
	}
	for _, allowed := range c.PostLogoutRedirectURIs {
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

// appDomain returns the host portion of a redirect URI, for display ("the app
// at jelly.example.com").
func appDomain(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	return u.Host
}
