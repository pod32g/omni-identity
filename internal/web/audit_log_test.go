package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureSlog swaps the default logger for a JSON capture buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestAuditEmitsStructuredLog(t *testing.T) {
	srv := testServer(t)
	buf := captureSlog(t)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "203.0.113.7:5555"

	// A failed login must log at WARN with the useful fields.
	srv.audit(req, evtLoginFailed, auditEntry{username: "alice", detail: "bad password"})
	// A successful one at INFO.
	srv.audit(req, evtLoginSuccess, auditEntry{actorUserID: "u1", username: "alice", success: true})

	out := buf.String()
	for _, want := range []string{
		`"msg":"login.failed"`, `"event":"login.failed"`, `"username":"alice"`,
		`"detail":"bad password"`, `"ip":"203.0.113.7"`, `"level":"WARN"`,
		`"msg":"login.success"`, `"actor":"u1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestAuditLevelMapping(t *testing.T) {
	for _, e := range []string{evtLoginFailed, evtLoginLocked, evtMFAFailed, evtConsentDenied} {
		if auditLevel(e) != slog.LevelWarn {
			t.Errorf("%s should be WARN", e)
		}
	}
	if auditLevel(evtLoginSuccess) != slog.LevelInfo {
		t.Error("login.success should be INFO")
	}
}
