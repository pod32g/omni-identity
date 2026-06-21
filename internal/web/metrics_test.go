package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsEndpointExposesEnrichedSeries(t *testing.T) {
	srv := testServer(t)
	srv.metrics.recordLogin("ldap", "success")
	srv.metrics.recordLogin("local", "failure")
	srv.metrics.recordMFA("challenge")
	srv.metrics.recordMFA("success")
	srv.metrics.recordToken("access")
	srv.metrics.recordToken("refresh")

	rr := do(srv, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`omni_identity_logins_total{source="ldap",result="success"} 1`,
		`omni_identity_logins_total{source="local",result="failure"} 1`,
		`omni_identity_mfa_total{result="challenge"} 1`,
		`omni_identity_mfa_total{result="success"} 1`,
		`omni_identity_tokens_issued_total{type="access"} 1`,
		`omni_identity_tokens_issued_total{type="refresh"} 1`,
		`omni_identity_build_info{version=`,
		`omni_identity_active_sessions `,
		`omni_identity_http_requests_total`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n--- got ---\n%s", want, body)
		}
	}
}
