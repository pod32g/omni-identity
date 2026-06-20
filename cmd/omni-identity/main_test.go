package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHealthcheckSucceedsOn2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := runHealthcheck([]string{"--url", srv.URL}); err != nil {
		t.Errorf("healthcheck should succeed on 200: %v", err)
	}
}

func TestHealthcheckFailsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := runHealthcheck([]string{"--url", srv.URL}); err == nil {
		t.Error("healthcheck should fail on 503")
	}
}

func TestHealthcheckFailsOnUnreachable(t *testing.T) {
	if err := runHealthcheck([]string{"--url", "http://127.0.0.1:0/", "--timeout", "1s"}); err == nil {
		t.Error("healthcheck should fail when the target is unreachable")
	}
}

func TestBackupAndIntegritySubcommands(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "omni.db")
	// Create the DB by running integrity (which opens+migrates it).
	if err := runIntegrity([]string{"--db", dbPath}); err != nil {
		t.Fatalf("integrity on fresh db: %v", err)
	}
	out := filepath.Join(t.TempDir(), "snap.db")
	if err := runBackup([]string{"--db", dbPath, "--out", out}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := runBackup([]string{"--db", dbPath}); err == nil {
		t.Error("backup without --out should error")
	}
}
