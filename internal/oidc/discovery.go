// Package oidc implements the OpenID Connect provider logic: discovery, PKCE,
// the authorization-code flow, token issuance, and userinfo.
package oidc

import "strings"

// Standard OIDC scopes supported by Omni Identity.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// DiscoveryDocument is the OpenID Provider Metadata served at
// /.well-known/openid-configuration.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// BuildDiscovery returns the discovery document for the given issuer base URL.
// All endpoint URLs are derived from the issuer, so the issuer must be the
// public base URL clients use to reach this server.
func BuildDiscovery(issuer string) DiscoveryDocument {
	base := strings.TrimRight(issuer, "/")
	return DiscoveryDocument{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/oauth2/authorize",
		TokenEndpoint:                     base + "/oauth2/token",
		UserinfoEndpoint:                  base + "/userinfo",
		JWKSURI:                           base + "/jwks.json",
		RevocationEndpoint:                base + "/oauth2/revoke",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "EdDSA"},
		ScopesSupported:                   []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat",
			"email", "email_verified", "preferred_username", "name",
		},
	}
}
