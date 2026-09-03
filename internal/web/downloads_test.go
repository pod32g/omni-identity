package web

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadsPageAndArtifactServing(t *testing.T) {
	srv := testServer(t)
	dir := t.TempDir()
	body := []byte("fake agent binary")
	if err := os.WriteFile(filepath.Join(dir, "omni-enrollment-linux-arm64"), body, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0o644)
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "sub", "secret"), []byte("no"), 0o644)
	srv.downloads = newDownloadsService(dir)
	sum := sha256.Sum256(body)

	alice := createUser(t, srv, "alice", "pw", false)
	req := httptest.NewRequest(http.MethodGet, "/account/enroll", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: startSession(t, srv, alice.ID)})
	rr := do(srv, req)
	if rr.Code != 200 {
		t.Fatalf("enroll page = %d", rr.Code)
	}
	page := rr.Body.String()
	for _, want := range []string{"/downloads/omni-enrollment-linux-arm64", hex.EncodeToString(sum[:]), "omni-enrollment --issuer http://localhost:8080 --allow-insecure-http", "omni-enrollment enroll --issuer http://localhost:8080", "arm64 (Raspberry Pi"} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(page, ".hidden") || strings.Contains(page, "secret") {
		t.Error("hidden or nested files listed")
	}

	rr = do(srv, httptest.NewRequest(http.MethodGet, "/downloads/omni-enrollment-linux-arm64", nil))
	if rr.Code != 200 || rr.Body.String() != string(body) || rr.Header().Get("X-Checksum-SHA256") != hex.EncodeToString(sum[:]) {
		t.Errorf("download = %d headers=%v", rr.Code, rr.Header())
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment") {
		t.Error("missing attachment disposition")
	}
	for _, p := range []string{"/downloads/.hidden", "/downloads/sub%2Fsecret", "/downloads/..%2Fomni.db", "/downloads/nope"} {
		if rr := do(srv, httptest.NewRequest(http.MethodGet, p, nil)); rr.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, rr.Code)
		}
	}
	// Anonymous users are sent to login for the page but may fetch artifacts.
	if rr := do(srv, httptest.NewRequest(http.MethodGet, "/account/enroll", nil)); rr.Code != http.StatusSeeOther {
		t.Errorf("anonymous page = %d", rr.Code)
	}
}

func TestDownloadsDisabled(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	req := httptest.NewRequest(http.MethodGet, "/account/enroll", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: startSession(t, srv, alice.ID)})
	if rr := do(srv, req); rr.Code != 200 || !strings.Contains(rr.Body.String(), "not enabled") {
		t.Errorf("disabled page = %d", rr.Code)
	}
	if rr := do(srv, httptest.NewRequest(http.MethodGet, "/downloads/omni-enrollment-linux-amd64", nil)); rr.Code != http.StatusNotFound {
		t.Errorf("download with no dir = %d", rr.Code)
	}
}
