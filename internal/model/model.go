// Package model holds the core domain types shared across the store and the
// HTTP/OIDC layers. Keeping them in one dependency-free package avoids import
// cycles between persistence and handlers.
package model

import "time"

// Client type constants.
const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

// User is a local account.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	IsAdmin      bool
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Session is a browser login session.
type Session struct {
	ID         string
	UserID     string
	CSRFSecret string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Client is a registered OAuth2/OIDC client application.
type Client struct {
	ClientID         string
	ClientSecretHash string
	Name             string
	RedirectURIs     []string
	AllowedScopes    []string
	Type             string
	Disabled         bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// IsPublic reports whether the client is a public (no-secret) client.
func (c *Client) IsPublic() bool { return c.Type == ClientTypePublic }

// AuthorizationCode is a single-use code issued by the authorize endpoint.
type AuthorizationCode struct {
	CodeHash            string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
	CreatedAt           time.Time
}

// RefreshToken is a stored, hashed refresh token (supports rotation).
type RefreshToken struct {
	ID          string
	TokenHash   string
	ClientID    string
	UserID      string
	Scope       string
	RotatedFrom string
	Revoked     bool
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// SigningKey is a JWT signing keypair.
type SigningKey struct {
	KID        string
	Alg        string
	PublicJWK  string
	PrivatePEM string
	Active     bool
	CreatedAt  time.Time
}
