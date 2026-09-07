package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Revocation push: when a device or user loses access, tell the configured
// Omni Access gateways at once (revocation.webhooks) so they drop sessions
// immediately instead of waiting for the device revalidation window. The
// message is a short-lived JWT this server signs with its own key; the
// gateway verifies it against the JWKS it already trusts. Best effort and
// asynchronous: a gateway that is down simply falls back to the window.

const revocationTokenTTL = 2 * time.Minute

// pushRevocation notifies every configured gateway that subject (a user
// sub) and/or deviceID has been revoked. Either may be empty.
func (s *Server) pushRevocation(subject, deviceID, reason string) {
	hooks := s.cfg.Revocation.Webhooks
	if len(hooks) == 0 || (subject == "" && deviceID == "") {
		return
	}
	tok, err := s.issuer.IssueRevocationToken(subject, deviceID, reason, revocationTokenTTL)
	if err != nil {
		return
	}
	body, _ := json.Marshal(map[string]string{"subject": subject, "device_id": deviceID, "reason": reason})
	for _, url := range hooks {
		url := url
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
		}()
	}
}
