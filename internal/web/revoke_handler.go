package web

import (
	"net/http"

	"github.com/pod32g/omni-identity/internal/auth"
)

// handleRevoke implements RFC 7009 token revocation for refresh tokens.
// Access tokens are stateless JWTs and cannot be individually revoked; per the
// RFC, an unsupported or unknown token still yields a 200 response.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	client, ok := s.authenticateClient(r)
	if !ok {
		oauthClientAuthError(w)
		return
	}

	if raw := r.PostFormValue("token"); raw != "" {
		if rt, err := s.db.GetRefreshTokenByHash(r.Context(), auth.HashToken(raw)); err == nil {
			if rt.ClientID == client.ClientID {
				_ = s.db.RevokeRefreshToken(r.Context(), rt.ID)
				s.audit(r, evtTokenRevoked, auditEntry{actorUserID: rt.UserID, clientID: client.ClientID, success: true})
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
