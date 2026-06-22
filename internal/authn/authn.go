// Package authn defines the pluggable authentication-connector contract used to
// federate external identity sources (LDAP today; SAML/social/SCIM later). It is
// a dependency-free leaf package so both connector implementations
// (internal/ldap) and the web layer can import it without cycles.
//
// The interface follows the established IdP pattern (cf. Dex's connector model):
// a connector verifies a username/password and returns a normalized Identity,
// distinguishing "invalid credentials" (a normal negative) from operational
// errors the operator must see.
package authn

import "context"

// Identity is a verified external identity returned by a connector. It is mapped
// onto a local mirror user (just-in-time provisioning) by the web layer.
type Identity struct {
	Connector   string // connector id, e.g. "ldap"; stored as users.auth_source
	ExternalID  string // stable id within the source (e.g. the LDAP entry DN)
	Username    string
	Email       string
	DisplayName string
	IsAdmin     bool // resolved from the source (e.g. admin-group membership)
}

// PasswordConnector verifies a username/password pair against an external
// identity source.
//
// Login reports ok=false for an unknown user or wrong password — a normal
// negative result, NOT an error — so callers can map every such case to one
// generic, non-enumerating message. A non-nil err is reserved for transport or
// configuration failures (unreachable server, bad bind account, TLS problems)
// that the operator should see in logs and that must never leak to the browser.
type PasswordConnector interface {
	// ID returns the stable connector identifier (e.g. "ldap").
	ID() string
	// Login verifies credentials and returns the resolved Identity.
	Login(ctx context.Context, username, password string) (id Identity, ok bool, err error)
}

// DirectoryUser is the mutable profile of a directory entry, used when creating
// or updating a user in the backing directory. Surname (sn) is required by the
// inetOrgPerson schema; implementations default it from DisplayName/Username
// when empty.
type DirectoryUser struct {
	Username    string
	Email       string
	DisplayName string // cn
	Surname     string // sn
}

// DirectoryManager is implemented by a connector that can write to its backing
// directory, turning Omni into a management UI over a canonical directory (the
// directory remains the source of truth). It is optional: the web layer holds a
// nil DirectoryManager unless a managed directory is configured.
//
// Every method performs a single directory write and returns a non-nil error on
// failure; nothing is committed to Omni's local mirror until the directory write
// succeeds (directory-first). Errors are operational and safe to surface to an
// authenticated admin.
type DirectoryManager interface {
	// ID returns the stable connector identifier (matches the user's auth_source).
	ID() string
	// CreateUser adds a new entry and returns its distinguished name (DN), which
	// the caller stores as the mirror user's ExternalID.
	CreateUser(ctx context.Context, u DirectoryUser) (dn string, err error)
	// UpdateUser replaces the mutable attributes (mail, cn) of the entry at dn.
	UpdateUser(ctx context.Context, dn string, u DirectoryUser) error
	// SetPassword sets the entry's password via the RFC 3062 password-modify
	// extended operation.
	SetPassword(ctx context.Context, dn, password string) error
	// DeleteUser removes the entry at dn.
	DeleteUser(ctx context.Context, dn string) error
}
