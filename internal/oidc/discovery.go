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
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	PromptValuesSupported             []string `json:"prompt_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported"`
}

// Grant types beyond the core code/refresh/client_credentials set.
const (
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code" // RFC 8628
	GrantTypeJWTBearer  = "urn:ietf:params:oauth:grant-type:jwt-bearer"  // RFC 7523 §2.1
	// GrantTypeTokenExchange (RFC 8693) lets an enrolled device broker
	// audience-scoped tokens for local applications.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// BuildDiscovery returns the discovery document. The issuer is the value
// tokens carry and clients are configured with; the endpoints are built on
// publicURL, the address browsers and clients should reach this server at.
// They are usually the same. They differ while the server is put behind a
// TLS-terminating gateway without changing the issuer every relying party
// and enrolled device knows: the issuer stays, the endpoints move to HTTPS.
// An empty publicURL means "same as the issuer".
func BuildDiscovery(issuer, publicURL string) DiscoveryDocument {
	iss := strings.TrimRight(issuer, "/")
	base := strings.TrimRight(publicURL, "/")
	if base == "" {
		base = iss
	}
	return DiscoveryDocument{
		Issuer:                            iss,
		AuthorizationEndpoint:             base + "/oauth2/authorize",
		TokenEndpoint:                     base + "/oauth2/token",
		UserinfoEndpoint:                  base + "/userinfo",
		DeviceAuthorizationEndpoint:       base + "/oauth2/device_authorization",
		JWKSURI:                           base + "/jwks.json",
		RevocationEndpoint:                base + "/oauth2/revoke",
		IntrospectionEndpoint:             base + "/oauth2/introspect",
		EndSessionEndpoint:                base + "/logout",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials", GrantTypeDeviceCode, GrantTypeJWTBearer, GrantTypeTokenExchange},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "EdDSA"},
		ScopesSupported:                   []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess, ScopeDeviceEnroll},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		PromptValuesSupported:             []string{"none", "login", "consent"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat",
			"email", "email_verified", "preferred_username", "name",
			"auth_time", "amr", "device_id", "device_trust", "act", "groups",
		},
		DPoPSigningAlgValuesSupported: []string{"EdDSA", "ES256", "RS256"},
	}
}
