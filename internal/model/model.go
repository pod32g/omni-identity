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
	// Authentication source: "local" (default) or a connector id such as "ldap".
	// External users have no local password and are provisioned just-in-time on
	// first login; ExternalID is the stable id within that source (e.g. the LDAP
	// entry DN).
	AuthSource string
	ExternalID string
	// Account lockout bookkeeping.
	FailedLoginCount int
	LockedUntil      time.Time // zero = not locked
	// Multi-factor authentication (TOTP).
	MFAEnabled bool
	TOTPSecret string // AES-GCM ciphertext (base64), empty when MFA disabled
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IsLocal reports whether the account authenticates against the local password
// store (as opposed to an external directory such as LDAP). Local-password flows
// (reset, set-password, change-password) only apply to local accounts.
func (u *User) IsLocal() bool { return u.AuthSource == "" || u.AuthSource == "local" }

// IsLocked reports whether the account is currently locked out.
func (u *User) IsLocked(now time.Time) bool {
	return !u.LockedUntil.IsZero() && now.Before(u.LockedUntil)
}

// Locked is a no-argument convenience for templates (uses wall-clock now).
func (u *User) Locked() bool { return u.IsLocked(time.Now().UTC()) }

// Session is a browser login session.
type Session struct {
	ID         string
	UserID     string
	CSRFSecret string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time // zero when never updated; used for idle timeout
	AMR        string    // space-separated auth methods (e.g. "pwd mfa")
}

// AuditEvent is a recorded security-relevant event.
type AuditEvent struct {
	ID          string
	CreatedAt   time.Time
	Event       string
	ActorUserID string
	Username    string
	ClientID    string
	IP          string
	UserAgent   string
	Success     bool
	Detail      string
}

// Password token purposes.
const (
	PasswordTokenActivation = "activation"
	PasswordTokenReset      = "reset"
)

// PasswordToken is a hashed, single-use, expiring token for new-account
// activation or password reset.
type PasswordToken struct {
	ID        string
	UserID    string
	TokenHash string
	Purpose   string
	Used      bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RecoveryCode is a hashed, single-use MFA recovery code.
type RecoveryCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt time.Time
}

// LoginChallenge is a pending second-factor step issued after a correct
// password but before a session is granted.
type LoginChallenge struct {
	ID        string
	UserID    string
	Next      string
	Req       string
	CreatedAt time.Time
	ExpiresAt time.Time
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

// Settings holds the admin-editable runtime configuration (single global row).
// Durations are stored as strings (Go duration syntax) and parsed by the web
// layer, matching how the YAML config handles them.
type Settings struct {
	Issuer                    string
	PublicURL                 string
	TokenTTL                  string
	RefreshTokenTTL           string
	MaxFailedLogins           int
	LockoutDuration           string
	RateLimitWindow           string
	LoginIPMaxAttempts        int
	PasswordVerifyConcurrency int
	MaxLoginUsernameBytes     int
	MaxLoginPasswordBytes     int
	AllowLoopbackHTTPRedirect bool
	PasswordMinLength         int
	RequireUpper              bool
	RequireLower              bool
	RequireNumber             bool
	RequireSymbol             bool
	SessionIdleTimeout        string
	SessionLifetime           string
	CookieSecure              bool
	MaxLogoBytes              int
	// LDAPManageEnabled toggles directory write management (create/edit/delete/
	// set-password for LDAP users) live from the admin panel. Seeded from
	// config (ldap.manage_enabled); only effective when a write-capable bind is
	// configured.
	LDAPManageEnabled bool
	// Logging verbosity, live-editable. LogLevel is debug|info|warn|error;
	// LogHTTPRequests is all|errors|off. Seeded from config (logging.*).
	LogLevel        string
	LogHTTPRequests string
	Seeded          bool
	UpdatedAt       time.Time
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
