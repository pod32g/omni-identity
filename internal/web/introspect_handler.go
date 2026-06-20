package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/oidc"
)

// handleIntrospect implements RFC 7662 token introspection. The caller must
// authenticate as a confidential client. It reports whether an access or
// refresh token is currently active and returns its metadata.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok || client.IsPublic() {
		// Introspection is restricted to authenticated confidential clients.
		oauthClientAuthError(w)
		return
	}

	token := r.PostFormValue("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	// Try as a JWT access token first. Per RFC 7662, a client may only learn
	// about its own tokens: the token's audience must be the calling client.
	if vt, err := s.issuer.Verify(token); err == nil && vt.IsAccessToken() && vt.Audience == client.ClientID {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     true,
			"token_type": "access_token",
			"sub":        vt.Subject,
			"aud":        vt.Audience,
			"scope":      vt.Scope,
			"client_id":  vt.Audience,
			"token_use":  "access",
		})
		return
	}

	// Then as a stored refresh token — again only when it belongs to the caller.
	if rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(token)); err == nil && rt.ClientID == client.ClientID {
		active := !rt.Revoked && time.Now().Before(rt.ExpiresAt)
		resp := map[string]any{"active": active}
		if active {
			resp["token_type"] = "refresh_token"
			resp["sub"] = rt.UserID
			resp["client_id"] = rt.ClientID
			resp["scope"] = rt.Scope
			resp["exp"] = rt.ExpiresAt.Unix()
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Unknown token, or one owned by another client: report inactive without
	// disclosing its existence.
	writeJSON(w, http.StatusOK, map[string]any{"active": false})
}

// grantClientCredentials implements the client_credentials grant for
// confidential clients (machine-to-machine). It issues an access token only —
// no id_token, no refresh token.
func (s *Server) grantClientCredentials(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(r)
	if !ok || client.IsPublic() {
		oauthClientAuthError(w)
		return
	}

	// Default to the client's full allowed scope; a requested scope must be a
	// subset. The openid scope is not valid without a user, so it is excluded.
	scope := r.PostFormValue("scope")
	allowed := nonOpenIDScopes(client.AllowedScopes)
	if scope == "" {
		scope = strings.Join(allowed, " ")
	} else if !oidc.ScopesSubset(oidc.SplitScope(scope), allowed) {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed for this client")
		return
	}

	access, err := s.issuer.IssueAccessToken(client.ClientID, client.ClientID, scope)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	s.audit(r, evtTokenIssued, auditEntry{clientID: client.ClientID, success: true, detail: "client_credentials"})
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.issuer.AccessTTL().Seconds()),
		Scope:       scope,
	})
}

// nonOpenIDScopes returns scopes excluding "openid" (meaningless without a user).
func nonOpenIDScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != oidc.ScopeOpenID {
			out = append(out, s)
		}
	}
	return out
}
