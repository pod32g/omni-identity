package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/model"
)

// A client that reports a hardware key backend earns "hardware" trust at
// enrollment; posture reports are stored, shown on /devices/me, and carried
// in exchanged tokens; an unknown backend is ignored.
func TestKeyBackendTrustAndPosture(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDeviceWith(t, srv, alice, key, "laptop", map[string]any{"key_backend": "secure-enclave"})
	dev, _ := srv.db.GetDevice(context.Background(), id)
	if dev.TrustLevel != model.DeviceTrustHardware || dev.KeyBackend != "secure-enclave" {
		t.Fatalf("enrolled with a Secure Enclave key: trust %q backend %q", dev.TrustLevel, dev.KeyBackend)
	}
	key2 := newDeviceKey(t)
	id2 := enrollDeviceWith(t, srv, alice, key2, "desktop", map[string]any{"key_backend": "nonsense"})
	dev2, _ := srv.db.GetDevice(context.Background(), id2)
	if dev2.TrustLevel != model.DeviceTrustEnrolled || dev2.KeyBackend != "" {
		t.Fatalf("unknown backend: trust %q backend %q", dev2.TrustLevel, dev2.KeyBackend)
	}

	access := decodeJSON(t, deviceToken(t, srv, id2, key2, true))["access_token"].(string)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/me/posture", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+access)
		key2.dpop(t, req, access)
		return do(srv, req)
	}
	if rr := post(`{"os_name":"Windows","os_version":"11 24H2","disk_encrypted":true,"screen_lock":false,"key_backend":"tpm"}`); rr.Code != http.StatusOK {
		t.Fatalf("posture: %d %s", rr.Code, rr.Body.String())
	}
	dev2, _ = srv.db.GetDevice(context.Background(), id2)
	if dev2.TrustLevel != model.DeviceTrustHardware || dev2.KeyBackend != "tpm" || dev2.PostureAt.IsZero() {
		t.Fatalf("after posture with a tpm key: trust %q backend %q at %v", dev2.TrustLevel, dev2.KeyBackend, dev2.PostureAt)
	}
	p := parsePosture(dev2.Posture)
	if p == nil || p.OSName != "Windows" || p.DiskEncrypted == nil || !*p.DiskEncrypted || p.ScreenLock == nil || *p.ScreenLock {
		t.Fatalf("stored posture: %+v", p)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
	req.Header.Set("Authorization", "DPoP "+access)
	key2.dpop(t, req, access)
	me := decodeJSON(t, do(srv, req))
	if me["trust_level"] != "hardware" || me["key_backend"] != "tpm" || me["posture"] == nil {
		t.Fatalf("/devices/me: %v", me)
	}
	if rr := post(`{"os_name":"` + strings.Repeat("x", 5000) + `"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized posture accepted: %d", rr.Code)
	}
}
