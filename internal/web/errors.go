package web

import (
	"log/slog"
	"net/http"
)

// renderError renders the shared, branded error page with a friendly message.
func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	s.tmpl.render(w, status, "error", map[string]any{"Message": message})
}

// renderOIDCError shows the user a friendly branded error page while logging the
// full detail server-side. logMsg is the server-side summary; logKV are
// alternating key/value pairs added to the structured log entry.
func (s *Server) renderOIDCError(w http.ResponseWriter, r *http.Request, status int, userMsg, logMsg string, logKV ...any) {
	attrs := append([]any{"path", r.URL.Path, "status", status}, logKV...)
	slog.Warn(logMsg, attrs...)
	s.renderError(w, status, userMsg)
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
