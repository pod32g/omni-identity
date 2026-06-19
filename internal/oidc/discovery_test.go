package oidc

import (
	"slices"
	"testing"
)

func TestBuildDiscoveryTrimsTrailingSlash(t *testing.T) {
	d := BuildDiscovery("https://id.example.com/")
	if d.Issuer != "https://id.example.com" {
		t.Errorf("issuer = %q, want trailing slash trimmed", d.Issuer)
	}
}

func TestBuildDiscoveryEndpoints(t *testing.T) {
	d := BuildDiscovery("https://id.example.com")
	cases := map[string]string{
		d.AuthorizationEndpoint: "https://id.example.com/oauth2/authorize",
		d.TokenEndpoint:         "https://id.example.com/oauth2/token",
		d.UserinfoEndpoint:      "https://id.example.com/userinfo",
		d.JWKSURI:               "https://id.example.com/jwks.json",
		d.RevocationEndpoint:    "https://id.example.com/oauth2/revoke",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("endpoint = %q, want %q", got, want)
		}
	}
}

func TestBuildDiscoveryCapabilities(t *testing.T) {
	d := BuildDiscovery("https://id.example.com")

	if !slices.Contains(d.ResponseTypesSupported, "code") {
		t.Error("must support response_type=code")
	}
	if !slices.Contains(d.GrantTypesSupported, "authorization_code") ||
		!slices.Contains(d.GrantTypesSupported, "refresh_token") {
		t.Error("must support authorization_code and refresh_token grants")
	}
	if !slices.Contains(d.CodeChallengeMethodsSupported, "S256") {
		t.Error("must advertise PKCE S256")
	}
	for _, alg := range []string{"RS256", "EdDSA"} {
		if !slices.Contains(d.IDTokenSigningAlgValuesSupported, alg) {
			t.Errorf("must advertise %s signing", alg)
		}
	}
	for _, scope := range []string{"openid", "profile", "email", "offline_access"} {
		if !slices.Contains(d.ScopesSupported, scope) {
			t.Errorf("must advertise scope %q", scope)
		}
	}
	if !slices.Contains(d.TokenEndpointAuthMethodsSupported, "none") {
		t.Error("must advertise 'none' auth method for public clients")
	}
}
