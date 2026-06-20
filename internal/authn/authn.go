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
