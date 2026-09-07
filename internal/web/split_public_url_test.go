package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/pop"
)

// Behind a TLS-terminating gateway the public URL moves to HTTPS while the
// issuer stays: discovery advertises HTTPS endpoints under the old issuer,
// and device proofs bound to either address are accepted.
func TestSplitPublicURLKeepsIssuerAndAcceptsBothProofTargets(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	key := newDeviceKey(t)
	id := enrollDevice(t, srv, alice, key, "laptop")
	access := decodeJSON(t, deviceToken(t, srv, id, key, true))["access_token"].(string)

	st, _ := srv.db.GetSettings(context.Background())
	st.PublicURL = "https://identity.example.dev"
	_ = srv.db.UpdateSettings(context.Background(), st)
	srv.settings.Reload(context.Background())
	if cur := srv.settings.Current(); cur.PublicURL != "https://identity.example.dev" || cur.Issuer != testBase {
		t.Fatalf("settings: public %q issuer %q", cur.PublicURL, cur.Issuer)
	}

	disc := decodeJSON(t, do(srv, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)))
	if disc["issuer"] != testBase || !strings.HasPrefix(disc["authorization_endpoint"].(string), "https://identity.example.dev/") ||
		!strings.HasPrefix(disc["token_endpoint"].(string), "https://identity.example.dev/") {
		t.Fatalf("discovery: %v", disc)
	}

	me := func(base string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/me", nil)
		req.Header.Set("Authorization", "DPoP "+access)
		proof, err := pop.NewProof(key.priv, req.Method, base+req.URL.Path, access, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("DPoP", proof)
		return do(srv, req).Code
	}
	if c := me(testBase); c != http.StatusOK {
		t.Errorf("proof bound to the issuer address: %d", c)
	}
	if c := me("https://identity.example.dev"); c != http.StatusOK {
		t.Errorf("proof bound to the public address: %d", c)
	}
	if c := me("https://evil.example"); c != http.StatusUnauthorized {
		t.Errorf("proof bound to a third party accepted: %d", c)
	}
}
