package web

import (
	"net/http"

	"github.com/pod32g/omni-identity/internal/oidc"
)

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := oidc.BuildDiscovery(s.cfg.Security.Issuer)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(s.keys.JWKS())
}
