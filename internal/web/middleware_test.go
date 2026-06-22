package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogHTTPRequestModes(t *testing.T) {
	cases := []struct {
		mode   string
		status int
		want   bool
	}{
		{"all", 200, true}, {"all", 404, true}, {"all", 500, true},
		{"errors", 200, false}, {"errors", 302, false}, {"errors", 404, true}, {"errors", 500, true},
		{"off", 200, false}, {"off", 500, false},
		{"", 200, true}, // unset/unknown falls back to logging
	}
	for _, c := range cases {
		if got := logHTTPRequest(c.mode, c.status); got != c.want {
			t.Errorf("logHTTPRequest(%q, %d) = %v, want %v", c.mode, c.status, got, c.want)
		}
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy")
	}
	if rr.Header().Get("Permissions-Policy") == "" {
		t.Error("missing Permissions-Policy")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
}

func TestAuthPagesUseNoStore(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}
}

func TestMetricsEndpointRequiresToken(t *testing.T) {
	srv := testServer(t)
	do(srv, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	do(srv, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))

	rr := do(srv, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code without configured token = %d, want 404", rr.Code)
	}

	srv.cfg.Metrics.BearerToken = "test-metrics-token"
	rr = do(srv, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code without bearer token = %d, want 401", rr.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-metrics-token")
	rr = do(srv, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "omni_identity_http_requests_total") {
		t.Error("metrics missing request total counter")
	}
}

func TestRecovererCatchesPanic(t *testing.T) {
	srv := testServer(t)
	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	rr := httptest.NewRecorder()
	srv.recoverer(panicking).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500 after panic", rr.Code)
	}
}
