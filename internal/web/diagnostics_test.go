package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceDiagnosticsUploadAndAdminView(t *testing.T) {
	srv := testServer(t)
	srv.cfg.Diagnostics.Dir = filepath.Join(t.TempDir(), "diag")
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)

	upload := func(body string, bound bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/me/diagnostics", strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Authorization", "DPoP "+access)
		if bound {
			key.dpop(t, req, access)
		}
		return do(srv, req)
	}
	if rr := upload("hello", false); rr.Code != http.StatusUnauthorized {
		t.Fatalf("upload without proof: %d", rr.Code)
	}
	if rr := upload("   \n", true); rr.Code != http.StatusBadRequest {
		t.Fatalf("empty upload: %d %s", rr.Code, rr.Body.String())
	}
	if rr := upload(strings.Repeat("x", maxDiagnosticsBytes+1), true); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: %d", rr.Code)
	}
	rr := upload("agent.log line 1\nhandshake failed reason=agent_error\n", true)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	name, _ := decodeJSON(t, rr)["stored"].(string)
	if !diagName.MatchString(name) {
		t.Fatalf("stored name %q", name)
	}
	raw, err := os.ReadFile(filepath.Join(srv.cfg.Diagnostics.Dir, id, name))
	if err != nil || !strings.Contains(string(raw), "agent_error") {
		t.Fatalf("stored file: %v %q", err, raw)
	}

	// Admin sees it listed and can open it as plain text; nobody else can.
	sid := adminSession(t, srv)
	page := adminGet(srv, "/admin/devices/"+id, sid)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "/diagnostics/"+name) {
		t.Fatalf("admin page: %d listing missing", page.Code)
	}
	file := adminGet(srv, "/admin/devices/"+id+"/diagnostics/"+name, sid)
	if file.Code != http.StatusOK || !strings.HasPrefix(file.Header().Get("Content-Type"), "text/plain") || !strings.Contains(file.Body.String(), "agent_error") {
		t.Fatalf("admin file: %d %s %s", file.Code, file.Header().Get("Content-Type"), file.Body.String())
	}
	if anon := adminGet(srv, "/admin/devices/"+id+"/diagnostics/"+name, ""); anon.Code == http.StatusOK {
		t.Fatalf("anonymous read of diagnostics: %d", anon.Code)
	}
	if bad := adminGet(srv, "/admin/devices/"+id+"/diagnostics/..%2F..%2Fetc%2Fpasswd", sid); bad.Code != http.StatusNotFound {
		t.Fatalf("traversal name: %d", bad.Code)
	}
}

func TestDeviceDiagnosticsKeepsTenAndDisabledByDefault(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/me/diagnostics", strings.NewReader("x"))
	req.Header.Set("Authorization", "DPoP "+access)
	key.dpop(t, req, access)
	if rr := do(srv, req); rr.Code != http.StatusNotFound {
		t.Fatalf("disabled uploads accepted: %d", rr.Code)
	}

	dir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 13; i++ {
		name := "20260101T0000" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "Z.log"
		_ = os.WriteFile(filepath.Join(dir, name), []byte("l"), 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600)
	pruneDiagnostics(dir)
	files := listDiagnostics(dir)
	if len(files) != keepDiagnostics || files[0].Name != "20260101T000012Z.log" {
		t.Fatalf("after prune: %d files, first %q", len(files), files[0].Name)
	}
}
