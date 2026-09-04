package web

import (
	"testing"

	"github.com/pod32g/omni-identity/internal/model"
)

// A native app's loopback redirect (RFC 8252 §7.3) lands on an ephemeral
// port; the form-action CSP source must therefore carry a wildcard port or
// browsers that enforce form-action across redirects (Chrome) block the
// consent/login submission.
func TestClientRedirectOriginsLoopbackWildcardPort(t *testing.T) {
	c := &model.Client{RedirectURIs: []string{
		"http://127.0.0.1/callback", "http://[::1]/callback",
		"http://127.0.0.1:8080/fixed", "https://app.example/cb", "http://app.example:3002/cb",
	}}
	got := clientRedirectOrigins(c)
	want := []string{"http://127.0.0.1:*", "http://[::1]:*", "http://127.0.0.1:8080", "https://app.example", "http://app.example:3002"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("origin %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}
