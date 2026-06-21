package web

import (
	"net/http"
	"strings"

	"github.com/pod32g/omni-identity/internal/oidc"
)

// handleUserinfo returns identity claims for the bearer access token, filtered
// by the token's granted scopes.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}

	vt, err := s.issuer.Verify(raw)
	if err != nil || !vt.IsAccessToken() {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return
	}

	user, err := s.db.GetUserByID(r.Context(), vt.Subject)
	if err != nil || user.Disabled {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "user is not available")
		return
	}

	claims := map[string]any{"sub": user.ID}
	if oidc.HasScope(vt.Scope, oidc.ScopeEmail) {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	if oidc.HasScope(vt.Scope, oidc.ScopeProfile) {
		claims["preferred_username"] = user.Username
		claims["name"] = user.Username
	}
	writeJSON(w, http.StatusOK, claims)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}
