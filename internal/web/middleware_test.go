package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
}

func TestMetricsEndpointReportsCounts(t *testing.T) {
	srv := testServer(t)
	do(srv, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	do(srv, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))

	rr := do(srv, httptest.NewRequest(http.MethodGet, "/metrics", nil))
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
