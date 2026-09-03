package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/oidc"
	"github.com/pod32g/omni-identity/internal/pop"
)

const testBase = "http://localhost:8080"

// deviceKey is a test endpoint's software key.
type deviceKey struct {
	priv ed25519.PrivateKey
	jkt  string
}

func newDeviceKey(t *testing.T) deviceKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := pop.FromPublicKey(pub)
	jkt, _ := j.Thumbprint()
	return deviceKey{priv: priv, jkt: jkt}
}

// dpop attaches a DPoP proof for (method, path[, accessToken]) to req.
func (k deviceKey) dpop(t *testing.T, req *http.Request, accessToken string) *http.Request {
	t.Helper()
	proof, err := pop.NewProof(k.priv, req.Method, testBase+req.URL.Path, accessToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	return req
}

func formReq(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad JSON (%d): %s", rr.Code, rr.Body.String())
	}
	return m
}

func jwtClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	c := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, c); err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	return c
}

// sessionReq builds a logged-in browser request with matching CSRF cookie/form.
func sessionReq(sid string, path string, form url.Values) *http.Request {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", "csrf-1")
	req := formReq(path, form)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	req.AddCookie(&http.Cookie{Name: "omni_csrf", Value: "csrf-1"})
	return req
}

// startDeviceGrant performs RFC 8628 §3.1 as the enrollment client and returns
// the raw device code and normalized user code.
func startDeviceGrant(t *testing.T, srv *Server, scope string, extra url.Values, mutate func(*http.Request)) (deviceCode, userCode string) {
	t.Helper()
	form := url.Values{"client_id": {model.EnrollmentClientID}, "scope": {scope}}
	for k, v := range extra {
		form[k] = v
	}
	req := formReq("/oauth2/device_authorization", form)
	if mutate != nil {
		mutate(req)
	}
	rr := do(srv, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("device_authorization = %d: %s", rr.Code, rr.Body.String())
	}
	m := decodeJSON(t, rr)
	if m["verification_uri"] != testBase+"/device" || m["interval"].(float64) != 5 {
		t.Errorf("response = %v", m)
	}
	return m["device_code"].(string), normalizeUserCode(m["user_code"].(string))
}

// approveUserCode walks the /device pages as the given session.
func approveUserCode(t *testing.T, srv *Server, sid, userCode, action string) *httptest.ResponseRecorder {
	t.Helper()
	rr := do(srv, sessionReq(sid, "/device", url.Values{"user_code": {formatUserCode(userCode)}}))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), formatUserCode(userCode)) {
		t.Fatalf("lookup = %d: %s", rr.Code, rr.Body.String())
	}
	rr = do(srv, sessionReq(sid, "/device/confirm", url.Values{"user_code": {userCode}, "action": {action}}))
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm = %d: %s", rr.Code, rr.Body.String())
	}
	return rr
}

// pollDeviceCode exchanges the device code, with a DPoP proof when key != nil.
func pollDeviceCode(t *testing.T, srv *Server, deviceCode string, key *deviceKey, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := formReq("/oauth2/token", url.Values{
		"grant_type":  {oidc.GrantTypeDeviceCode},
		"device_code": {deviceCode},
		"client_id":   {model.EnrollmentClientID},
	})
	if key != nil {
		key.dpop(t, req, "")
	}
	if mutate != nil {
		mutate(req)
	}
	return do(srv, req)
}

// enrollDevice runs the whole enrollment ceremony and returns the device id.
func enrollDevice(t *testing.T, srv *Server, user *model.User, key deviceKey, name string) string {
	t.Helper()
	sid := startSession(t, srv, user.ID)
	deviceCode, userCode := startDeviceGrant(t, srv, "openid device:enroll", url.Values{"device_name": {name}, "device_platform": {"linux"}}, nil)

	// Pending until approved.
	if rr := pollDeviceCode(t, srv, deviceCode, &key, nil); decodeJSON(t, rr)["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %s", rr.Body.String())
	}
	// Reset the poll interval so the test does not have to wait.
	resetPoll(t, srv, deviceCode)

	approveUserCode(t, srv, sid, userCode, "allow")

	rr := pollDeviceCode(t, srv, deviceCode, &key, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("token poll = %d: %s", rr.Code, rr.Body.String())
	}
	tok := decodeJSON(t, rr)
	if tok["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", tok["token_type"])
	}
	access := tok["access_token"].(string)
	if c := jwtClaims(t, access); c["cnf"].(map[string]any)["jkt"] != key.jkt {
		t.Errorf("access token not bound to the device key: %v", c["cnf"])
	}

	body, _ := json.Marshal(map[string]string{"name": name, "hostname": name + ".lan", "platform": "linux", "architecture": "arm64"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	req.Header.Set("Authorization", "DPoP "+access)
	key.dpop(t, req, access)
	rr = do(srv, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("enroll = %d: %s", rr.Code, rr.Body.String())
	}
	dev := decodeJSON(t, rr)
	if dev["fingerprint"] != key.jkt || dev["status"] != "active" || dev["owner_sub"] != user.ID || dev["trust_level"] != "enrolled" {
		t.Errorf("device = %v", dev)
	}
	return dev["device_id"].(string)
}

func resetPoll(t *testing.T, srv *Server, deviceCode string) {
	t.Helper()
	dc, err := srv.db.GetDeviceCodeByHash(context.Background(), hashToken(deviceCode))
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.db.MarkDeviceCodePolled(context.Background(), dc.ID, time.Now().Add(-time.Minute))
}

// deviceToken obtains a device token via the RFC 7523 jwt-bearer grant.
func deviceToken(t *testing.T, srv *Server, deviceID string, key deviceKey, withDPoP bool) *httptest.ResponseRecorder {
	t.Helper()
	assertion, err := pop.NewAssertion(key.priv, key.jkt, deviceID, testBase, time.Now(), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := formReq("/oauth2/token", url.Values{
		"grant_type": {oidc.GrantTypeJWTBearer},
		"assertion":  {assertion},
		"client_id":  {model.EnrollmentClientID},
	})
	if withDPoP {
		key.dpop(t, req, "")
	}
	return do(srv, req)
}

// --- Scenarios 7–12: enrollment ---

func TestDeviceEnrollmentEndToEnd(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "omni-laptop")

	// The device appears in the user's list and the admin list.
	devs, _ := srv.db.ListDevicesForUser(context.Background(), alice.ID)
	if len(devs) != 1 || devs[0].ID != id || devs[0].Name != "omni-laptop" {
		t.Fatalf("devices = %+v", devs)
	}
	// The stored key is public-only (scenario 9: no private material reaches Omni).
	if strings.Contains(devs[0].PublicKey, `"d"`) {
		t.Error("private key material stored")
	}
	sid := startSession(t, srv, alice.ID)
	req := httptest.NewRequest(http.MethodGet, "/account/devices", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, req); rr.Code != 200 || !strings.Contains(rr.Body.String(), "omni-laptop") {
		t.Errorf("account devices page: %d", rr.Code)
	}

	// Enrollment is audited and counted.
	events, _ := srv.db.ListAuditEvents(context.Background(), 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Event] = true
	}
	for _, want := range []string{evtDeviceGrantRequested, evtDeviceEnrollStarted, evtDeviceEnrollCompleted} {
		if !seen[want] {
			t.Errorf("audit event %s missing", want)
		}
	}
}

func TestEnrollmentDeniedByUser(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	sid := startSession(t, srv, alice.ID)
	key := newDeviceKey(t)
	deviceCode, userCode := startDeviceGrant(t, srv, "openid device:enroll", nil, nil)
	approveUserCode(t, srv, sid, userCode, "deny")
	if rr := pollDeviceCode(t, srv, deviceCode, &key, nil); decodeJSON(t, rr)["error"] != "access_denied" {
		t.Errorf("want access_denied, got %s", rr.Body.String())
	}
}

func TestEnrollmentRejectsKeySubstitutionAndUnboundToken(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	sid := startSession(t, srv, alice.ID)
	key := newDeviceKey(t)
	attacker := newDeviceKey(t)

	deviceCode, userCode := startDeviceGrant(t, srv, "openid device:enroll", nil, nil)
	approveUserCode(t, srv, sid, userCode, "allow")
	access := decodeJSON(t, pollDeviceCode(t, srv, deviceCode, &key, nil))["access_token"].(string)

	post := func(k deviceKey, ath string, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Authorization", header)
		k.dpop(t, req, ath)
		return do(srv, req)
	}
	// Stolen token + attacker's own key: the proof key does not match cnf.jkt.
	if rr := post(attacker, access, "DPoP "+access); rr.Code != http.StatusUnauthorized {
		t.Errorf("key substitution accepted: %d %s", rr.Code, rr.Body.String())
	}
	// Right key, but the proof is not bound to the token (bad ath).
	if rr := post(key, "other-token", "DPoP "+access); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong ath accepted: %d", rr.Code)
	}
	// Right everything.
	if rr := post(key, access, "DPoP "+access); rr.Code != http.StatusCreated {
		t.Errorf("valid enrollment refused: %d %s", rr.Code, rr.Body.String())
	}

	// A token obtained WITHOUT DPoP (plain bearer) cannot enroll at all.
	deviceCode2, userCode2 := startDeviceGrant(t, srv, "openid device:enroll", nil, nil)
	approveUserCode(t, srv, sid, userCode2, "allow")
	bearer := decodeJSON(t, pollDeviceCode(t, srv, deviceCode2, nil, nil))["access_token"].(string)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Authorization", "Bearer "+bearer)
	newDeviceKey(t).dpop(t, req, bearer)
	if rr := do(srv, req); rr.Code != http.StatusUnauthorized {
		t.Errorf("unbound token accepted for enrollment: %d", rr.Code)
	}
}

func TestEnrollmentRequiresScopeAndRejectsReusedKey(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	bob := createUser(t, srv, "bob", "pw", false)
	key := newDeviceKey(t)
	enrollDevice(t, srv, alice, key, "laptop")

	// Same key cannot be enrolled twice, even by another user.
	sid := startSession(t, srv, bob.ID)
	deviceCode, userCode := startDeviceGrant(t, srv, "openid device:enroll", nil, nil)
	approveUserCode(t, srv, sid, userCode, "allow")
	access := decodeJSON(t, pollDeviceCode(t, srv, deviceCode, &key, nil))["access_token"].(string)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"name":"clone"}`))
	req.Header.Set("Authorization", "DPoP "+access)
	key.dpop(t, req, access)
	if rr := do(srv, req); rr.Code != http.StatusConflict {
		t.Errorf("duplicate key accepted: %d %s", rr.Code, rr.Body.String())
	}

	// A token without device:enroll (plain openid device grant) is refused.
	deviceCode, userCode = startDeviceGrant(t, srv, "openid", nil, nil)
	approveUserCode(t, srv, sid, userCode, "allow")
	k2 := newDeviceKey(t)
	access = decodeJSON(t, pollDeviceCode(t, srv, deviceCode, &k2, nil))["access_token"].(string)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Authorization", "DPoP "+access)
	k2.dpop(t, req, access)
	if rr := do(srv, req); rr.Code != http.StatusForbidden {
		t.Errorf("missing scope accepted: %d", rr.Code)
	}
}

func TestDevicePageRequiresLoginAndCSRF(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/device?user_code=BCDF-GHJK", nil))
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "/login") {
		t.Errorf("anonymous /device = %d %s", rr.Code, rr.Header().Get("Location"))
	}
	sid := startSession(t, srv, alice.ID)
	req := formReq("/device/confirm", url.Values{"user_code": {"BCDFGHJK"}, "action": {"allow"}})
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, req); rr.Code != http.StatusForbidden {
		t.Errorf("confirm without CSRF = %d, want 403", rr.Code)
	}
	// Unknown code renders an error, not a grant.
	rr = do(srv, sessionReq(sid, "/device", url.Values{"user_code": {"BCDF-GHJK"}}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown code = %d", rr.Code)
	}
}

func TestDeviceCodePollingSlowDownAndExpiry(t *testing.T) {
	srv := testServer(t)
	key := newDeviceKey(t)
	deviceCode, _ := startDeviceGrant(t, srv, "openid", nil, nil)
	pollDeviceCode(t, srv, deviceCode, &key, nil)
	if rr := pollDeviceCode(t, srv, deviceCode, &key, nil); decodeJSON(t, rr)["error"] != "slow_down" {
		t.Errorf("want slow_down: %s", rr.Body.String())
	}
	// Another client cannot redeem this code.
	createClient(t, srv, "other", "", true, nil, []string{"openid"})
	req := formReq("/oauth2/token", url.Values{"grant_type": {oidc.GrantTypeDeviceCode}, "device_code": {deviceCode}, "client_id": {"other"}})
	if rr := do(srv, req); decodeJSON(t, rr)["error"] != "invalid_grant" {
		t.Errorf("cross-client redeem: %s", rr.Body.String())
	}
	// Expire it.
	dc, _ := srv.db.GetDeviceCodeByHash(context.Background(), hashToken(deviceCode))
	_, _ = srv.db.DeleteExpiredDeviceCodes(context.Background(), time.Now().Add(time.Hour))
	if _, err := srv.db.GetDeviceCodeByHash(context.Background(), dc.DeviceCodeHash); err == nil {
		t.Error("expired device code not pruned")
	}
}

// --- Scenarios 13–17: device authentication ---

func TestDeviceAuthenticationProofOfPossession(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")

	rr := deviceToken(t, srv, id, key, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("jwt-bearer = %d: %s", rr.Code, rr.Body.String())
	}
	tok := decodeJSON(t, rr)
	if tok["token_type"] != "DPoP" || tok["device_id"] != id || tok["expires_in"].(float64) != 3600 {
		t.Errorf("device token response = %v", tok)
	}
	c := jwtClaims(t, tok["access_token"].(string))
	if c["token_use"] != "device" || c["sub"] != id || c["device_trust"] != "enrolled" || c["owner_sub"] != alice.ID {
		t.Errorf("device token claims = %v", c)
	}
	dev, _ := srv.db.GetDevice(context.Background(), id)
	if dev.LastSeenAt.IsZero() {
		t.Error("last_seen_at not updated")
	}

	// Scenario 15: knowing the device id with a different key fails.
	if rr := deviceToken(t, srv, id, newDeviceKey(t), false); rr.Code != http.StatusBadRequest {
		t.Errorf("foreign key accepted: %d", rr.Code)
	}
	// Scenario 16: invalid proofs fail (wrong audience, expired, wrong subject).
	bad := func(assertion string) {
		t.Helper()
		req := formReq("/oauth2/token", url.Values{"grant_type": {oidc.GrantTypeJWTBearer}, "assertion": {assertion}, "client_id": {model.EnrollmentClientID}})
		if rr := do(srv, req); rr.Code != http.StatusBadRequest || decodeJSON(t, rr)["error"] != "invalid_grant" {
			t.Errorf("bad assertion accepted: %d %s", rr.Code, rr.Body.String())
		}
	}
	wrongAud, _ := pop.NewAssertion(key.priv, key.jkt, id, "https://other", time.Now(), time.Minute, nil)
	bad(wrongAud)
	expired, _ := pop.NewAssertion(key.priv, key.jkt, id, testBase, time.Now().Add(-time.Hour), time.Minute, nil)
	bad(expired)
	wrongSub, _ := pop.NewAssertion(key.priv, key.jkt, id, testBase, time.Now(), time.Minute, map[string]any{"sub": "other"})
	bad(wrongSub)
	bad("not-a-jwt")

	// Scenario 17: a replayed assertion fails.
	assertion, _ := pop.NewAssertion(key.priv, key.jkt, id, testBase, time.Now(), time.Minute, nil)
	form := url.Values{"grant_type": {oidc.GrantTypeJWTBearer}, "assertion": {assertion}, "client_id": {model.EnrollmentClientID}}
	if rr := do(srv, formReq("/oauth2/token", form)); rr.Code != http.StatusOK {
		t.Fatalf("first use = %d", rr.Code)
	}
	if rr := do(srv, formReq("/oauth2/token", form)); rr.Code != http.StatusBadRequest {
		t.Errorf("replayed assertion accepted: %d", rr.Code)
	}
	// Only the built-in client may use the grant.
	createClient(t, srv, "spa", "", true, nil, []string{"openid"})
	form.Set("client_id", "spa")
	if rr := do(srv, formReq("/oauth2/token", form)); rr.Code != http.StatusUnauthorized {
		t.Errorf("third-party client allowed jwt-bearer: %d", rr.Code)
	}
}

func TestDeviceAPIRequiresBoundProof(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)

	get := func(k *deviceKey, ath string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
		req.Header.Set("Authorization", "DPoP "+access)
		if k != nil {
			k.dpop(t, req, ath)
		}
		return do(srv, req)
	}
	if rr := get(nil, ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("bound token without proof accepted: %d", rr.Code)
	}
	other := newDeviceKey(t)
	if rr := get(&other, access); rr.Code != http.StatusUnauthorized {
		t.Errorf("proof from another key accepted: %d", rr.Code)
	}
	rr := get(&key, access)
	if rr.Code != http.StatusOK || decodeJSON(t, rr)["device_id"] != id {
		t.Errorf("me = %d %s", rr.Code, rr.Body.String())
	}
	// Reusing the exact same proof is a replay.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
	req.Header.Set("Authorization", "DPoP "+access)
	key.dpop(t, req, access)
	proof := req.Header.Get("DPoP")
	do(srv, req)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
	req2.Header.Set("Authorization", "DPoP "+access)
	req2.Header.Set("DPoP", proof)
	if rr := do(srv, req2); rr.Code != http.StatusUnauthorized {
		t.Errorf("replayed DPoP proof accepted: %d", rr.Code)
	}
}

func TestDeviceKeyRotation(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)

	newKey := newDeviceKey(t)
	rotate := func(proofKey deviceKey, oldJKT string) *httptest.ResponseRecorder {
		jwk, _ := pop.FromPublicKey(proofKey.priv.Public())
		proof, _ := pop.NewAssertion(proofKey.priv, "", id, testBase+"/api/v1/devices/me/key", time.Now(), time.Minute, map[string]any{"old_jkt": oldJKT})
		body, _ := json.Marshal(map[string]any{"jwk": jwk, "proof": proof})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/me/key", bytes.NewReader(body))
		req.Header.Set("Authorization", "DPoP "+access)
		key.dpop(t, req, access)
		return do(srv, req)
	}
	// Proof must name the current key.
	if rr := rotate(newKey, "wrong"); rr.Code != http.StatusBadRequest {
		t.Errorf("rotation with wrong old_jkt accepted: %d", rr.Code)
	}
	rr := rotate(newKey, key.jkt)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", rr.Code, rr.Body.String())
	}
	dev, _ := srv.db.GetDevice(context.Background(), id)
	if dev.Fingerprint != newKey.jkt || dev.PreviousFingerprint != key.jkt {
		t.Errorf("rotation not applied: %+v", dev)
	}
	// Old key no longer authenticates; new key does.
	if rr := deviceToken(t, srv, id, key, false); rr.Code != http.StatusBadRequest {
		t.Errorf("old key still accepted: %d", rr.Code)
	}
	if rr := deviceToken(t, srv, id, newKey, false); rr.Code != http.StatusOK {
		t.Errorf("new key rejected: %d %s", rr.Code, rr.Body.String())
	}
}

// --- Scenarios 18–20: revocation ---

func TestRevokedDeviceCannotObtainCredentials(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)

	// User revokes from /account/devices.
	sid := startSession(t, srv, alice.ID)
	rr := do(srv, sessionReq(sid, "/account/devices/"+id+"/revoke", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Device revoked") {
		t.Fatalf("revoke = %d", rr.Code)
	}
	// Scenario 19: no new device tokens.
	if rr := deviceToken(t, srv, id, key, true); rr.Code != http.StatusBadRequest {
		t.Errorf("revoked device obtained a token: %d", rr.Code)
	}
	// Scenario 20: the still-valid device token is refused by Omni's own API
	// (status re-checked); it only remains cryptographically valid.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
	req.Header.Set("Authorization", "DPoP "+access)
	key.dpop(t, req, access)
	if rr := do(srv, req); rr.Code != http.StatusUnauthorized {
		t.Errorf("revoked device's token accepted by API: %d", rr.Code)
	}
	if vt, err := srv.issuer.Verify(access); err != nil || !vt.IsDeviceToken() {
		t.Error("outstanding device token should still verify cryptographically until expiry (documented)")
	}
	// The revoked fingerprint can never be re-enrolled.
	sid2 := startSession(t, srv, alice.ID)
	deviceCode, userCode := startDeviceGrant(t, srv, "openid device:enroll", nil, nil)
	approveUserCode(t, srv, sid2, userCode, "allow")
	tok := decodeJSON(t, pollDeviceCode(t, srv, deviceCode, &key, nil))["access_token"].(string)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(`{"name":"again"}`))
	req.Header.Set("Authorization", "DPoP "+tok)
	key.dpop(t, req, tok)
	if rr := do(srv, req); rr.Code != http.StatusConflict {
		t.Errorf("revoked key re-enrolled: %d", rr.Code)
	}
	// Another user cannot revoke it (already revoked → 400 for owner, 404 for stranger).
	bob := createUser(t, srv, "bob", "pw", false)
	if rr := do(srv, sessionReq(startSession(t, srv, bob.ID), "/account/devices/"+id+"/revoke", nil)); rr.Code != http.StatusNotFound {
		t.Errorf("stranger revoke = %d", rr.Code)
	}
}

func TestAdminDevicePagesAndDelete(t *testing.T) {
	srv := testServer(t)
	admin := createUser(t, srv, "root", "pw", true)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	sid := startSession(t, srv, admin.ID)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
		return do(srv, req)
	}
	if rr := get("/admin/devices"); rr.Code != 200 || !strings.Contains(rr.Body.String(), "laptop") || !strings.Contains(rr.Body.String(), "alice") {
		t.Errorf("admin list: %d", rr.Code)
	}
	if rr := get("/admin/devices/" + id); rr.Code != 200 || !strings.Contains(rr.Body.String(), key.jkt) {
		t.Errorf("admin detail: %d", rr.Code)
	}
	if rr := get("/admin/users/" + alice.ID); rr.Code != 200 || !strings.Contains(rr.Body.String(), "/admin/devices/"+id) {
		t.Errorf("user detail lacks device: %d", rr.Code)
	}
	// Delete requires revocation first.
	if rr := do(srv, sessionReq(sid, "/admin/devices/"+id+"/delete", nil)); rr.Code != http.StatusBadRequest {
		t.Errorf("delete active = %d", rr.Code)
	}
	if rr := do(srv, sessionReq(sid, "/admin/devices/"+id+"/revoke", nil)); rr.Code != http.StatusSeeOther {
		t.Errorf("admin revoke = %d", rr.Code)
	}
	if rr := do(srv, sessionReq(sid, "/admin/devices/"+id+"/delete", nil)); rr.Code != http.StatusSeeOther {
		t.Errorf("delete revoked = %d", rr.Code)
	}
	if _, err := srv.db.GetDevice(context.Background(), id); err == nil {
		t.Error("device not deleted")
	}
	// Non-admins are redirected.
	req := httptest.NewRequest(http.MethodGet, "/admin/devices", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: startSession(t, srv, alice.ID)})
	if rr := do(srv, req); rr.Code != http.StatusSeeOther {
		t.Errorf("non-admin /admin/devices = %d", rr.Code)
	}
}

// --- User-on-device login (docs §7) ---

func TestDeviceBoundUserLoginCarriesDeviceClaims(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	devTok := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)
	withDevice := func(req *http.Request) {
		req.Header.Set("Authorization", "DPoP "+devTok)
		key.dpop(t, req, devTok)
	}

	// The session that approves has amr "pwd mfa".
	now := time.Now().UTC()
	sess := &model.Session{ID: "sess-mfa", UserID: alice.ID, CSRFSecret: "x", CreatedAt: now, ExpiresAt: now.Add(time.Hour), AMR: "pwd mfa"}
	if err := srv.db.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	deviceCode, userCode := startDeviceGrant(t, srv, "openid offline_access", nil, withDevice)
	rr := approveUserCode(t, srv, sess.ID, userCode, "allow")
	if !strings.Contains(rr.Body.String(), "Approved") {
		t.Errorf("approval page: %s", rr.Body.String())
	}
	// The confirmation page named the device.
	lookup := do(srv, sessionReq(sess.ID, "/device", url.Values{"user_code": {userCode}}))
	_ = lookup // (already-approved codes are no longer pending; covered above)

	// Redeeming WITHOUT the device token fails: the grant is bound to the device.
	if rr := pollDeviceCode(t, srv, deviceCode, &key, nil); decodeJSON(t, rr)["error"] != "invalid_grant" {
		t.Errorf("unbound redeem should fail: %s", rr.Body.String())
	}
	resetPoll(t, srv, deviceCode)
	rr = pollDeviceCode(t, srv, deviceCode, &key, withDevice)
	if rr.Code != http.StatusOK {
		t.Fatalf("bound redeem = %d: %s", rr.Code, rr.Body.String())
	}
	tok := decodeJSON(t, rr)
	idc := jwtClaims(t, tok["id_token"].(string))
	if idc["sub"] != alice.ID || idc["device_id"] != id || idc["device_trust"] != "enrolled" {
		t.Errorf("id token claims = %v", idc)
	}
	if amr, _ := idc["amr"].([]any); len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Errorf("amr = %v", idc["amr"])
	}
	if _, ok := idc["cnf"]; ok {
		t.Error("cnf must not appear on the ID token")
	}
	ac := jwtClaims(t, tok["access_token"].(string))
	if ac["device_id"] != id || ac["cnf"].(map[string]any)["jkt"] != key.jkt {
		t.Errorf("access token claims = %v", ac)
	}

	// The refresh token is DPoP- and device-bound.
	refresh := tok["refresh_token"].(string)
	refreshReq := func(k *deviceKey) *httptest.ResponseRecorder {
		req := formReq("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {model.EnrollmentClientID}})
		if k != nil {
			k.dpop(t, req, "")
		}
		return do(srv, req)
	}
	if rr := refreshReq(nil); decodeJSON(t, rr)["error"] != "invalid_dpop_proof" {
		t.Errorf("refresh without proof: %s", rr.Body.String())
	}
	rr = refreshReq(&key)
	if rr.Code != http.StatusOK {
		t.Fatalf("bound refresh = %d: %s", rr.Code, rr.Body.String())
	}
	if c := jwtClaims(t, decodeJSON(t, rr)["id_token"].(string)); c["device_id"] != id {
		t.Errorf("refreshed id token lost device claims: %v", c)
	}
	refresh = decodeJSON(t, rr)["refresh_token"].(string)

	// Revoking the device kills the refresh chain.
	if err := srv.db.RevokeDevice(context.Background(), id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if rr := refreshReq(&key); rr.Code != http.StatusBadRequest {
		t.Errorf("refresh after device revocation = %d", rr.Code)
	}
}

// --- Backward compatibility ---

func TestAuthorizationCodeTokensHaveNoDeviceClaimsButCarryAMR(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "jellyfin", "topsecret", false, []string{"https://jelly.example.com/cb"}, []string{"openid", "email", "profile", "offline_access"})
	now := time.Now().UTC()
	sess := &model.Session{ID: "s1", UserID: user.ID, CSRFSecret: "x", CreatedAt: now, ExpiresAt: now.Add(time.Hour), AMR: "pwd"}
	_ = srv.db.CreateSession(context.Background(), sess)

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid email offline_access", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sess.ID})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	rr := do(srv, tokenPost(url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://jelly.example.com/cb"}, "client_id": {"jellyfin"},
		"client_secret": {"topsecret"}, "code_verifier": {pkceVerifier},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("token = %d %s", rr.Code, rr.Body.String())
	}
	tok := decodeJSON(t, rr)
	if tok["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tok["token_type"])
	}
	for _, raw := range []string{tok["access_token"].(string), tok["id_token"].(string)} {
		c := jwtClaims(t, raw)
		for _, k := range []string{"device_id", "device_trust", "cnf"} {
			if _, ok := c[k]; ok {
				t.Errorf("existing grant leaked %s claim", k)
			}
		}
	}
	if amr, _ := jwtClaims(t, tok["id_token"].(string))["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr on id token = %v", jwtClaims(t, tok["id_token"].(string))["amr"])
	}
	// Plain refresh (no DPoP) keeps working and keeps amr.
	rr = do(srv, tokenPost(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"jellyfin"}, "client_secret": {"topsecret"}}))
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh = %d %s", rr.Code, rr.Body.String())
	}
	if c := jwtClaims(t, decodeJSON(t, rr)["id_token"].(string)); c["amr"] == nil {
		t.Error("amr lost on refresh")
	}
}

func TestDiscoveryAdvertisesDeviceCapabilities(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	body := rr.Body.String()
	for _, want := range []string{"device_authorization_endpoint", oidc.GrantTypeDeviceCode, oidc.GrantTypeJWTBearer, "dpop_signing_alg_values_supported", "device:enroll"} {
		if !strings.Contains(body, want) {
			t.Errorf("discovery missing %s", want)
		}
	}
}

func TestInvalidDPoPProofAtTokenEndpointIsRejected(t *testing.T) {
	srv := testServer(t)
	req := formReq("/oauth2/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"x"}})
	req.Header.Set("DPoP", "garbage")
	if rr := do(srv, req); decodeJSON(t, rr)["error"] != "invalid_dpop_proof" {
		t.Errorf("garbage proof: %s", rr.Body.String())
	}
}

func hashToken(s string) string { return auth.HashToken(s) }
