package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryEndpoint(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["jwks_uri"] != "http://localhost:8080/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
	if doc["token_endpoint"] != "http://localhost:8080/oauth2/token" {
		t.Errorf("token_endpoint = %v", doc["token_endpoint"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JWKS JSON: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Errorf("jwks has %d keys, want 2", len(doc.Keys))
	}
}
