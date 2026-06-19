package web

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/tokens"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleToken implements the OAuth2 token endpoint (authorization_code + refresh_token).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r)
	case "refresh_token":
		s.grantRefreshToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}

	rawCode := r.PostFormValue("code")
	if rawCode == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing code")
		return
	}

	code, err := s.db.ConsumeAuthCode(r.Context(), auth.HashToken(rawCode))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if code.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if code.RedirectURI != r.PostFormValue("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// PKCE verification.
	verifier := r.PostFormValue("code_verifier")
	if code.CodeChallenge != "" {
		if verifier == "" || !oidc.VerifyPKCE(verifier, code.CodeChallenge, code.CodeChallengeMethod) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	} else if client.IsPublic() {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE is required")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), code.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}

	s.issueTokens(w, r, client, user, code.Scope, code.Nonce, "")
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}

	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(raw))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	if rt.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token client mismatch")
		return
	}
	if rt.Revoked {
		// Reuse of an already-rotated token: revoke the whole chain.
		_ = s.db.RevokeRefreshTokensForUserClient(r.Context(), rt.UserID, rt.ClientID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), rt.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}

	// Optional down-scoping; new scope must be a subset of the original grant.
	scope := rt.Scope
	if requested := r.PostFormValue("scope"); requested != "" {
		if !oidc.ScopesSubset(oidc.SplitScope(requested), oidc.SplitScope(rt.Scope)) {
			oauthError(w, http.StatusBadRequest, "invalid_scope", "scope exceeds the original grant")
			return
		}
		scope = requested
	}

	// Rotate: revoke the presented token, then mint a fresh chain link.
	_ = s.db.RevokeRefreshToken(r.Context(), rt.ID)
	s.issueTokens(w, r, client, user, scope, "", rt.ID)
}

// issueTokens builds and writes the token response (access + optional id +
// optional rotated refresh).
func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, client *model.Client, user *model.User, scope, nonce, rotatedFrom string) {
	access, err := s.issuer.IssueAccessToken(user.ID, client.ClientID, scope)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}

	resp := tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.issuer.AccessTTL().Seconds()),
		Scope:       scope,
	}

	if oidc.HasScope(scope, oidc.ScopeOpenID) {
		idTok, err := s.issuer.IssueIDToken(user.ID, client.ClientID, profileFromUser(user), nonce, time.Now())
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "could not issue id token")
			return
		}
		resp.IDToken = idTok
	}

	if oidc.HasScope(scope, oidc.ScopeOfflineAccess) {
		rawRefresh := auth.RandomToken(32)
		now := time.Now().UTC()
		newRT := &model.RefreshToken{
			ID:          uuid.NewString(),
			TokenHash:   auth.HashToken(rawRefresh),
			ClientID:    client.ClientID,
			UserID:      user.ID,
			Scope:       scope,
			RotatedFrom: rotatedFrom,
			ExpiresAt:   now.Add(s.cfg.Security.RefreshTokenTTL),
			CreatedAt:   now,
		}
		if err := s.db.CreateRefreshToken(r.Context(), newRT); err == nil {
			resp.RefreshToken = rawRefresh
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// authenticateClient resolves and authenticates the client from Basic auth or
// POST body credentials.
func (s *Server) authenticateClient(r *http.Request) (*model.Client, bool) {
	clientID, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}
	if clientID == "" {
		return nil, false
	}
	client, err := s.db.GetClient(r.Context(), clientID)
	if err != nil || client.Disabled {
		return nil, false
	}
	if client.Type == model.ClientTypeConfidential {
		if secret == "" || !auth.SecretMatches(secret, client.ClientSecretHash) {
			return nil, false
		}
	}
	return client, true
}

// profileFromUser maps a user to ID-token identity claims. Admin-provisioned
// emails are treated as verified in V1.
func profileFromUser(u *model.User) tokens.Profile {
	return tokens.Profile{
		Email:             u.Email,
		EmailVerified:     true,
		PreferredUsername: u.Username,
		Name:              u.Username,
	}
}
