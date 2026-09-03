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
	// WebAuthnHandle is the random, opaque user handle presented to
	// authenticators (base64url, 32 bytes). Empty until the first passkey is
	// registered. Never the user id: the handle is visible to authenticators.
	WebAuthnHandle string
	CreatedAt      time.Time
	UpdatedAt      time.Time
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
	AMR       string // first-factor methods already satisfied (e.g. "pwd", "webauthn user")
	CreatedAt time.Time
	ExpiresAt time.Time
}

// WebAuthnCredential is a registered passkey / security key. Credential holds
// the library's credential record as JSON (public key, flags, sign counter,
// transports) — no secrets.
type WebAuthnCredential struct {
	ID             string // base64url credential id
	UserID         string
	Name           string
	Credential     string
	AAGUID         string
	BackupEligible bool
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// WebAuthn ceremony purposes.
const (
	WebAuthnPurposeRegister = "register"
	WebAuthnPurposeLogin    = "login"
)

// WebAuthnCeremony is the server-side half of a pending WebAuthn ceremony:
// the challenge and options issued at begin, consumed once at finish.
type WebAuthnCeremony struct {
	ID          string
	UserID      string // empty for a discoverable (usernameless) login
	Purpose     string
	SessionData string // library SessionData JSON
	Next        string
	Req         string
	CreatedAt   time.Time
	ExpiresAt   time.Time
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

// EnrollmentClientID is the built-in public client used by the omni-enrollment
// endpoint agent (created by migration 0013). It is the only client allowed to
// request the device:enroll scope by default.
const EnrollmentClientID = "omni-enrollment"

// BuiltIn reports whether the client ships with Omni Identity and therefore
// cannot be deleted from the admin UI.
func (c *Client) BuiltIn() bool { return c.ClientID == EnrollmentClientID }

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
	Issuer                          string
	PublicURL                       string
	TokenTTL                        string
	RefreshTokenTTL                 string
	MaxFailedLogins                 int
	LockoutDuration                 string
	RateLimitWindow                 string
	LoginIPMaxAttempts              int
	PasswordVerifyConcurrency       int
	MaxLoginUsernameBytes           int
	MaxLoginPasswordBytes           int
	AllowLoopbackHTTPRedirect       bool
	AllowPrivateNetworkHTTPRedirect bool
	AllowPrivateSchemeRedirect      bool
	PasswordMinLength               int
	RequireUpper                    bool
	RequireLower                    bool
	RequireNumber                   bool
	RequireSymbol                   bool
	SessionIdleTimeout              string
	SessionLifetime                 string
	CookieSecure                    bool
	MaxLogoBytes                    int
	// LDAPManageEnabled toggles directory write management (create/edit/delete/
	// set-password for LDAP users) live from the admin panel. Seeded from
	// config (ldap.manage_enabled); only effective when a write-capable bind is
	// configured.
	LDAPManageEnabled bool
	// Logging verbosity, live-editable. LogLevel is debug|info|warn|error;
	// LogHTTPRequests is all|errors|off. Seeded from config (logging.*).
	LogLevel        string
	LogHTTPRequests string
	// DeviceTokenTTL is the lifetime of device tokens issued to enrolled devices.
	DeviceTokenTTL string
	// RequireDeviceApproval makes new enrollments pending until an admin approves.
	RequireDeviceApproval bool
	Seeded                bool
	UpdatedAt             time.Time
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
	// AMR is the space-separated list of authentication methods of the session
	// that authorized the code (RFC 8176 values), surfaced as the ID token amr.
	AMR string
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
	// AMR is preserved across rotation so refreshed ID tokens keep their amr.
	AMR string
	// DeviceID binds the token to an enrolled device: it is revoked with the
	// device and refreshed tokens carry device claims. Empty for ordinary tokens.
	DeviceID string
	// DPoPJKT is the RFC 7638 thumbprint of the DPoP key the token is bound to
	// (RFC 9449 §5). Empty means a plain bearer refresh token.
	DPoPJKT string
}

// Device status values.
const (
	DeviceStatusPending = "pending"
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
)

// Device trust levels. V1 has a single level; "hardware" is reserved for
// attested TPM / Secure Enclave keys.
const (
	DeviceTrustEnrolled = "enrolled"
)

// Device is an enrolled endpoint. Only the public half of its key pair is ever
// stored; the endpoint proves possession of the private key to authenticate.
type Device struct {
	ID                  string
	OwnerUserID         string
	Name                string
	Hostname            string
	Platform            string
	Architecture        string
	PublicKey           string // public JWK (JSON)
	PublicKeyAlgorithm  string // JWS alg: EdDSA | ES256 | RS256
	Fingerprint         string // RFC 7638 JWK thumbprint (base64url SHA-256)
	PreviousFingerprint string // set after a key rotation
	Status              string
	TrustLevel          string
	// OwnerOnly restricts device-bound logins to the device's owner.
	OwnerOnly  bool
	CreatedAt  time.Time
	EnrolledAt time.Time // zero when pending
	LastSeenAt time.Time // zero when never authenticated
	RevokedAt  time.Time // zero unless revoked
}

// IsActive reports whether the device may obtain credentials.
func (d *Device) IsActive() bool { return d.Status == DeviceStatusActive }

// IsPending reports whether the device awaits admin approval.
func (d *Device) IsPending() bool { return d.Status == DeviceStatusPending }

// Device-code (RFC 8628) grant states.
const (
	DeviceCodePending  = "pending"
	DeviceCodeApproved = "approved"
	DeviceCodeDenied   = "denied"
	DeviceCodeConsumed = "consumed"
)

// DeviceCode is a pending RFC 8628 device authorization grant. The device
// code is stored hashed; the user code is the short human-entered value.
type DeviceCode struct {
	ID             string
	DeviceCodeHash string
	UserCode       string
	ClientID       string
	Scope          string
	// DeviceID is set when the request was authenticated by an enrolled device
	// (a device-aware login); DeviceName/DevicePlatform are display metadata
	// supplied by an unenrolled client during enrollment.
	DeviceID       string
	DeviceName     string
	DevicePlatform string
	Status         string
	UserID         string    // approving user (set on approval)
	AMR            string    // approving session's auth methods
	AuthTime       time.Time // approving session's login time
	LastPolledAt   time.Time
	CreatedAt      time.Time
	ExpiresAt      time.Time
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
