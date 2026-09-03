package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/tokens"
)

// RFC 8693 token exchange, used by the endpoint's local token broker
// (docs/DEVICE-IDENTITY-ARCHITECTURE.md §10): the enrolled device presents the
// user's device-bound refresh token as the subject and its own device token
// as the actor and receives a short-lived access token for a local
// application's audience. The issued token names the user in sub and the
// device in act, so a resource server can tell "alice, via her enrolled
// laptop" from a plain user token.

// RFC 8693 token type identifiers.
const (
	tokenTypeAccess  = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeRefresh = "urn:ietf:params:oauth:token-type:refresh_token"
)

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

func (s *Server) grantTokenExchange(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok || !client.BuiltIn() {
		oauthClientAuthError(w)
		return
	}
	f := r.PostForm
	if f.Get("subject_token_type") != tokenTypeRefresh {
		oauthError(w, http.StatusBadRequest, "invalid_request", "subject_token_type must be "+tokenTypeRefresh)
		return
	}
	if f.Get("actor_token_type") != tokenTypeAccess || f.Get("actor_token") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "an actor_token of type "+tokenTypeAccess+" (device token) is required")
		return
	}
	if rt := f.Get("requested_token_type"); rt != "" && rt != tokenTypeAccess {
		oauthError(w, http.StatusBadRequest, "invalid_request", "only access tokens can be requested")
		return
	}
	audience := strings.TrimSpace(f.Get("audience"))
	if audience == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "audience is required")
		return
	}
	jkt := dpopJKT(r)
	if jkt == "" {
		oauthError(w, http.StatusBadRequest, "invalid_dpop_proof", "token exchange requires a DPoP proof from the device key")
		return
	}

	// Actor: the device, proven by its DPoP-bound device token.
	actor, err := s.issuer.Verify(f.Get("actor_token"))
	if err != nil || !actor.IsDeviceToken() || actor.JKT == "" || actor.JKT != jkt {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "actor_token must be a DPoP-bound device token for the presented key")
		return
	}
	dev, err := s.db.GetDevice(r.Context(), actor.Subject)
	if err != nil || !dev.IsActive() {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "device is not active")
		return
	}

	// Subject: the user's refresh token, bound to the same device and key.
	rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(f.Get("subject_token")))
	if err != nil || rt.Revoked || time.Now().After(rt.ExpiresAt) || rt.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is not a valid refresh token")
		return
	}
	if rt.DeviceID != dev.ID || rt.DPoPJKT != jkt {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is not bound to the acting device")
		return
	}
	user, err := s.db.GetUserByID(r.Context(), rt.UserID)
	if err != nil || user.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not available")
		return
	}

	// Audience: a registered, enabled client; scope ⊆ the grant ∩ the audience's allowed scopes.
	target, err := s.db.GetClient(r.Context(), audience)
	if err != nil || target.Disabled {
		oauthError(w, http.StatusBadRequest, "invalid_target", "unknown audience")
		return
	}
	scope := strings.TrimSpace(f.Get("scope"))
	if scope == "" {
		scope = strings.Join(intersectScopes(oidc.SplitScope(rt.Scope), target.AllowedScopes), " ")
	}
	requested := oidc.SplitScope(scope)
	if len(requested) == 0 || !oidc.ScopesSubset(requested, oidc.SplitScope(rt.Scope)) || !oidc.ScopesSubset(requested, target.AllowedScopes) {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "scope must be within the user's grant and the audience's allowed scopes")
		return
	}

	// The broker hands this to a local app that has no device key, so it is
	// a plain bearer token: short-lived, audience-bound, delegation recorded.
	extra := tokens.Extra{
		"device_id":    dev.ID,
		"device_trust": dev.TrustLevel,
		"act":          map[string]any{"sub": dev.ID},
	}
	if rt.AMR != "" {
		extra["amr"] = tokens.AMRList(rt.AMR)
	}
	// The exchange is not a fresh authentication: the token reports when the
	// user actually signed in, so a resource server can apply its own
	// freshness policy.
	if !rt.AuthTime.IsZero() {
		extra["auth_time"] = rt.AuthTime.Unix()
	}
	extra = withGroups(extra, user)
	access, err := s.issuer.IssueAccessTokenWithClaims(user.ID, target.ClientID, scope, extra)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	s.metrics.recordToken("access")
	s.audit(r, evtTokenIssued, auditEntry{actorUserID: user.ID, username: user.Username, clientID: target.ClientID,
		success: true, detail: "token_exchange device=" + dev.ID})
	writeJSON(w, http.StatusOK, tokenExchangeResponse{
		AccessToken: access, IssuedTokenType: tokenTypeAccess, TokenType: "Bearer",
		ExpiresIn: int(s.issuer.AccessTTL().Seconds()), Scope: scope,
	})
}

func intersectScopes(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
