package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

// Personal access tokens: a signed-in device creates a long-lived, device-bound
// bearer token, lists it, revokes it, and revocation shows up in the list a
// gateway polls. Also: revoking the device cascades to its tokens.
func TestPersonalAccessTokens(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "omni-metrics", "s3cret", false, []string{"https://m.example/cb"}, []string{"openid", "email", "profile"})
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	devTok := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)
	withDevice := func(req *http.Request) {
		req.Header.Set("Authorization", "DPoP "+devTok)
		key.dpop(t, req, devTok)
	}
	// Device-bound user login → device-bound refresh token.
	deviceCode, userCode := startDeviceGrant(t, srv, "openid profile email offline_access", nil, withDevice)
	approveUserCode(t, srv, startSession(t, srv, alice.ID), userCode, "allow")
	refresh := decodeJSON(t, pollDeviceCode(t, srv, deviceCode, &key, withDevice))["refresh_token"].(string)

	createPAT := func(fields map[string]any) *httptest.ResponseRecorder {
		fields["refresh_token"] = refresh
		body, _ := json.Marshal(fields)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/me/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		withDevice(req)
		return do(srv, req)
	}

	// Create a token.
	rr := createPAT(map[string]any{"name": "cron", "audience": "omni-metrics", "scope": "openid email", "expires_in": 3600})
	if rr.Code != http.StatusOK {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeJSON(t, rr)
	token, _ := created["token"].(string)
	jti, _ := created["id"].(string)
	if token == "" || jti == "" {
		t.Fatalf("create response missing token/id: %v", created)
	}
	// The token is a real, verifiable access token with device delegation + pat marker.
	c := jwtClaims(t, token)
	if c["sub"] != alice.ID || c["aud"] != "omni-metrics" || c["device_id"] != id || c["pat"] != true {
		t.Errorf("pat claims = %v", c)
	}
	if c["act"].(map[string]any)["sub"] != id {
		t.Errorf("pat not device-delegated: %v", c["act"])
	}
	if c["scope"] != "openid email" {
		t.Errorf("scope = %v", c["scope"])
	}

	// List shows it.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me/tokens", nil)
	withDevice(listReq)
	lrr := do(srv, listReq)
	if lrr.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", lrr.Code, lrr.Body.String())
	}
	var listed struct {
		Tokens []map[string]any `json:"tokens"`
	}
	_ = json.Unmarshal(lrr.Body.Bytes(), &listed)
	if len(listed.Tokens) != 1 || listed.Tokens[0]["id"] != jti || listed.Tokens[0]["name"] != "cron" {
		t.Fatalf("list = %v", listed.Tokens)
	}
	if _, leaked := listed.Tokens[0]["token"]; leaked {
		t.Error("list must not return the secret token")
	}

	// Not yet in the revoked-tokens list.
	if inRevoked(t, srv, jti) {
		t.Error("token revoked before we asked")
	}

	// Revoke it.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/me/tokens/"+jti, nil)
	withDevice(delReq)
	if drr := do(srv, delReq); drr.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", drr.Code, drr.Body.String())
	}
	if !inRevoked(t, srv, jti) {
		t.Error("revoked token not in the revoked list")
	}
	// A second revoke is a 404 (already revoked / not active).
	delReq2 := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/me/tokens/"+jti, nil)
	withDevice(delReq2)
	if drr := do(srv, delReq2); drr.Code != http.StatusNotFound {
		t.Errorf("double revoke = %d", drr.Code)
	}

	// Cascade: a new token dies when the device is revoked.
	rr2 := createPAT(map[string]any{"name": "deploy", "audience": "omni-metrics", "expires_in": 3600})
	jti2 := decodeJSON(t, rr2)["id"].(string)
	if inRevoked(t, srv, jti2) {
		t.Fatal("second token pre-revoked")
	}
	if err := srv.db.RevokeDevice(context.Background(), id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !inRevoked(t, srv, jti2) {
		t.Error("device revocation did not cascade to its tokens")
	}

	// Widening beyond the user's grant is refused.
	if rr := createPAT(map[string]any{"audience": "omni-metrics", "scope": "offline_access"}); rr.Code == http.StatusOK {
		t.Errorf("widening scope allowed: %s", rr.Body.String())
	}
	_ = model.EnrollmentClientID
}

func inRevoked(t *testing.T, srv *Server, jti string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/revoked-tokens", nil)
	rr := do(srv, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoked-tokens = %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		JTIs []string `json:"jtis"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	for _, x := range out.JTIs {
		if x == jti {
			return true
		}
	}
	return false
}
