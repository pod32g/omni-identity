package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// ensureEnv points the commands at a fresh instance the way a container does:
// through the environment, with no config file.
func ensureEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OMNI_SERVER_PUBLIC_URL", "https://id.example.com")
	t.Setenv("OMNI_SECURITY_ISSUER", "https://id.example.com")
	t.Setenv("OMNI_DATABASE_PATH", filepath.Join(t.TempDir(), "omni.db"))
}

func TestAdminEnsureCommand(t *testing.T) {
	ensureEnv(t)
	noConfig := filepath.Join(t.TempDir(), "absent.yaml")
	run := func(stdin string, args ...string) (map[string]any, error) {
		var out bytes.Buffer
		err := runAdminEnsure(append([]string{"--config", noConfig}, args...), strings.NewReader(stdin), &out)
		var res map[string]any
		if err == nil {
			if jerr := json.Unmarshal(out.Bytes(), &res); jerr != nil {
				t.Fatalf("stdout is not one JSON object: %q", out.String())
			}
		}
		return res, err
	}

	res, err := run("correct horse battery 9\n", "--username", "root", "--email", "root@example.com", "--password-stdin")
	if err != nil || res["result"] != "created" {
		t.Fatalf("first run = %v, %v", res, err)
	}
	// Repeating it, even with no password at all, is a no-op.
	res, err = run("", "--username", "root", "--email", "root@example.com")
	if err != nil || res["result"] != "unchanged" {
		t.Fatalf("second run = %v, %v", res, err)
	}
	if _, err := run("short\n", "--username", "other", "--email", "other@example.com", "--password-stdin"); err == nil {
		t.Error("a password below the policy was accepted")
	}
	if _, err := run("", "--username", "other", "--email", "other@example.com", "--password-stdin"); err == nil {
		t.Error("an empty password on stdin was accepted")
	}
}

func TestClientEnsureCommand(t *testing.T) {
	ensureEnv(t)
	noConfig := filepath.Join(t.TempDir(), "absent.yaml")
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (map[string]any, string, error) {
		var out bytes.Buffer
		err := runClientEnsure(append([]string{"--config", noConfig}, args...), strings.NewReader(""), &out)
		var res map[string]any
		if err == nil {
			if jerr := json.Unmarshal(out.Bytes(), &res); jerr != nil {
				t.Fatalf("stdout is not one JSON object: %q", out.String())
			}
		}
		return res, out.String(), err
	}
	base := []string{"--id", "omni-control", "--name", "Omni Control", "--secret-file", secretFile,
		"--redirect-uri", "https://control.example.com/auth/callback",
		"--post-logout-redirect-uri", "https://control.example.com/", "--skip-consent"}

	res, raw, err := run(base...)
	if err != nil || res["result"] != "created" {
		t.Fatalf("create = %v, %v", res, err)
	}
	if strings.Contains(raw, "0123456789abcdef") || strings.Contains(raw, "client_secret") {
		t.Errorf("a caller-supplied secret was printed: %s", raw)
	}
	if res, _, err = run(base...); err != nil || res["result"] != "unchanged" {
		t.Fatalf("repeat = %v, %v", res, err)
	}

	// Only the flags given are enforced: this changes the redirect URIs and
	// leaves the name, the post-logout URI and skip-consent alone.
	res, _, err = run("--id", "omni-control", "--redirect-uri", "https://control.example.com/auth/callback",
		"--redirect-uri", "https://control2.example.com/auth/callback")
	if err != nil || res["result"] != "updated" || fmt.Sprint(res["changed"]) != "[redirect_uris]" {
		t.Fatalf("partial update = %v, %v", res, err)
	}
	if res, _, err = run(base...); err != nil || fmt.Sprint(res["changed"]) != "[redirect_uris]" {
		t.Fatalf("restoring the full spec = %v, %v (the partial update must not have touched other fields)", res, err)
	}
	// An explicit empty value clears a list.
	if res, _, err = run("--id", "omni-control", "--post-logout-redirect-uri", ""); err != nil || fmt.Sprint(res["changed"]) != "[post_logout_redirect_uris]" {
		t.Fatalf("clearing post-logout URIs = %v, %v", res, err)
	}

	if _, _, err := run("--id", "plain", "--name", "Plain", "--redirect-uri", "http://app.example.com/cb"); err == nil {
		t.Error("a public http redirect URI was accepted")
	}
	if _, _, err := run("--name", "No id", "--redirect-uri", "https://x.example.com/cb"); err == nil {
		t.Error("a missing --id was accepted")
	}
}
