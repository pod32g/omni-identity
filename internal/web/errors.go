package web

import "net/http"

// renderError renders the shared error page.
func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	s.tmpl.render(w, status, "error", map[string]any{"Message": message})
}

// oauthError writes an RFC 6749 error response as JSON.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// oauthClientAuthError writes a 401 invalid_client response with a challenge.
func oauthClientAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="omni-identity"`)
	oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
}
