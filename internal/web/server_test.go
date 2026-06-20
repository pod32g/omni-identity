package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{}
	cfg.Server.PublicURL = "http://localhost:8080"
	cfg.Security.Issuer = "http://localhost:8080"
	cfg.Security.TokenTTL = 15 * time.Minute
	cfg.Security.RefreshTokenTTL = 720 * time.Hour
	cfg.Security.MaxFailedLogins = 5
	cfg.Security.LockoutDuration = 15 * time.Minute
	cfg.Security.PasswordMinLength = 12
	srv, err := NewServer(cfg, db)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestHealthzReturnsOK(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want ok", body["status"])
	}
}
