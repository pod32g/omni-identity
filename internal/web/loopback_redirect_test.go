package web

import (
	"testing"

	"github.com/pod32g/omni-identity/internal/model"
)

func TestLoopbackRedirectIgnoresPortPerRFC8252(t *testing.T) {
	c := &model.Client{RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback", "https://app.example/cb", "http://localhost:9000/cb"}}
	for uri, want := range map[string]bool{
		"http://127.0.0.1:53211/callback":  true,
		"http://127.0.0.1/callback":        true,
		"http://[::1]:40000/callback":      true,
		"http://127.0.0.1:53211/other":     false,
		"http://127.0.0.1:53211/callback?x": false,
		"https://127.0.0.1:53211/callback": false,
		"http://localhost:9001/cb":         false, // localhost is exact-match only
		"http://localhost:9000/cb":         true,
		"https://app.example:8443/cb":      false, // non-loopback never ignores the port
		"http://127.0.0.2:5/callback":      false,
	} {
		if got := redirectURIAllowed(c, uri); got != want {
			t.Errorf("%s: got %v want %v", uri, got, want)
		}
	}
}
