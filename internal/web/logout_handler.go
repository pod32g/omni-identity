package web

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/pod32g/omni-identity/internal/model"
)

// parseWithParam returns rawURL with key=value added to its query string.
func parseWithParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// handleLogoutPage implements OIDC RP-initiated logout (GET /logout).
//
// It clears the Omni Identity session, and — when a valid id_token_hint
// identifies the user and client — revokes that browser's refresh tokens for
// the client. If a post_logout_redirect_uri is supplied and exactly matches the
// identified client's allowlist, the browser is redirected there (with state);
// otherwise the branded signed-out page is shown.
func (s *Server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hint := q.Get("id_token_hint")
	postLogout := q.Get("post_logout_redirect_uri")
	state := q.Get("state")

	var userID string
	var client *model.Client
	if hint != "" {
		vt, err := s.issuer.ParseIDTokenHint(hint)
		if err != nil {
			slog.Warn("logout: invalid id_token_hint", "error", err.Error())
		} else {
			userID = vt.Subject
			if c, err := s.db.GetClient(r.Context(), vt.Audience); err == nil {
				client = c
			}
		}
	}

	// Always clear the local session, regardless of hint validity.
	if err := s.sessions.Destroy(w, r); err != nil {
		slog.Error("logout: destroy session", "error", err.Error())
	}

	// Revoke this user+client's refresh tokens when we could identify both.
	if userID != "" && client != nil {
		if err := s.db.RevokeRefreshTokensForUserClient(r.Context(), userID, client.ClientID); err != nil {
			slog.Error("logout: revoke refresh tokens", "error", err.Error())
		}
	}

	// Only honor post_logout_redirect_uri when it exactly matches the identified
	// client's allowlist — never an open redirect.
	if postLogout != "" && client != nil && postLogoutRedirectAllowed(client, postLogout) {
		dest := postLogout
		if state != "" {
			if u, err := parseWithParam(postLogout, "state", state); err == nil {
				dest = u
			}
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	if postLogout != "" && (client == nil || !postLogoutRedirectAllowed(client, postLogout)) {
		slog.Warn("logout: post_logout_redirect_uri rejected", "uri", postLogout)
	}
	s.renderSignedOut(w, r, "")
}
