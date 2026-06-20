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
	// Display metadata surfaced on the hosted login/consent pages.
	DisplayName            string
	LogoURL                string
	HomepageURL            string
	PostLogoutRedirectURIs []string
	// SkipConsent marks a first-party/trusted client whose authorizations do not
	// require an interactive consent screen.
	SkipConsent bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsPublic reports whether the client is a public (no-secret) client.
func (c *Client) IsPublic() bool { return c.Type == ClientTypePublic }

// Label returns the friendliest available name for the client: its display
// name when set, otherwise its registered name, otherwise the client id.
func (c *Client) Label() string {
	switch {
	case c.DisplayName != "":
		return c.DisplayName
	case c.Name != "":
		return c.Name
	default:
		return c.ClientID
	}
}

// Branding holds the configurable look of the hosted pages (single global row).
type Branding struct {
	ProductName     string
	LogoBytes       []byte
	LogoContentType string
	AccentColor     string
	FooterText      string
	BackgroundStyle string
	UpdatedAt       time.Time
}

// AuthRequest is a pending OIDC authorization request parked across the hosted
// login and consent pages, keyed by an opaque id handed to the browser.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

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
	// AuthTime is when the end user actually authenticated (session login time).
	AuthTime time.Time
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
	// AuthTime is the original end-user authentication time, preserved across rotation.
	AuthTime time.Time
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
