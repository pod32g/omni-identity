package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The issuer an enrolled device trusts announces a new address in its
// discovery document; the client follows it once the new address confirms
// itself, and reports the move so the enrollment record can be updated.
func TestDiscoveryFollowsConfirmedIssuerMove(t *testing.T) {
	var newSrv *httptest.Server
	newSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": newSrv.URL, "token_endpoint": newSrv.URL + "/oauth2/token",
			"device_authorization_endpoint": newSrv.URL + "/oauth2/device_authorization"})
	}))
	defer newSrv.Close()
	oldSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": newSrv.URL, "token_endpoint": newSrv.URL + "/oauth2/token",
			"device_authorization_endpoint": newSrv.URL + "/oauth2/device_authorization"})
	}))
	defer oldSrv.Close()
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Names a third party it does not control.
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://evil.example", "token_endpoint": "https://evil.example/t",
			"device_authorization_endpoint": "https://evil.example/d"})
	}))
	defer impostor.Close()

	c := &Client{Issuer: oldSrv.URL, ClientID: "omni-enrollment", HTTP: oldSrv.Client(), AllowInsecureHTTP: true}
	var moved []string
	c.OnIssuerMoved = func(from, to string) { moved = append(moved, from, to) }
	d, err := c.discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if c.Issuer != newSrv.URL || d.TokenEndpoint != newSrv.URL+"/oauth2/token" {
		t.Fatalf("client did not move: issuer %s endpoints %+v", c.Issuer, d)
	}
	if len(moved) != 2 || moved[0] != oldSrv.URL || moved[1] != newSrv.URL {
		t.Fatalf("OnIssuerMoved = %v", moved)
	}

	// An issuer naming an address that does not confirm itself is refused.
	c2 := &Client{Issuer: impostor.URL, ClientID: "omni-enrollment", HTTP: impostor.Client(), AllowInsecureHTTP: true}
	if _, err := c2.discover(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unconfirmed move accepted: %v", err)
	}
	// Without AllowInsecureHTTP a plain-http destination is never followed.
	c3 := &Client{Issuer: oldSrv.URL, ClientID: "omni-enrollment", HTTP: oldSrv.Client()}
	if _, err := c3.discover(context.Background()); err == nil {
		t.Fatal("http move followed without AllowInsecureHTTP")
	}
}
