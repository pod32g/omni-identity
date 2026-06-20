// Package ldap implements an authn.PasswordConnector backed by an external LDAP
// / Active Directory server. It uses the standard go-ldap library and the
// conventional search-then-bind flow (the same approach used by Dex and other
// IdPs), so Omni acts as an LDAP client without reimplementing the protocol.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/pod32g/omni-identity/internal/authn"
)

// connectorID is the stable id for this connector; also stored as the user's
// auth_source.
const connectorID = "ldap"

// Config is the resolved client configuration (mirrors config.LDAPConfig with the
// preset already applied and Enabled stripped).
type Config struct {
	URL                string
	StartTLS           bool
	BindDN             string
	BindPassword       string
	BaseDN             string
	UserFilter         string
	AttrUsername       string
	AttrEmail          string
	AttrDisplayName    string
	AdminGroupDN       string
	GroupFilter        string
	CACertFile         string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Client is a configured LDAP password connector. It satisfies
// authn.PasswordConnector.
type Client struct {
	cfg     Config
	tlsConf *tls.Config
}

var _ authn.PasswordConnector = (*Client)(nil)

// New validates cfg and builds a Client.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("ldap: url is required")
	}
	if cfg.BaseDN == "" || cfg.UserFilter == "" {
		return nil, errors.New("ldap: base_dn and user_filter are required")
	}
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, errors.New("ldap: user_filter must contain %s")
	}
	if cfg.AttrUsername == "" {
		cfg.AttrUsername = "uid"
	}
	if cfg.AttrEmail == "" {
		cfg.AttrEmail = "mail"
	}
	if cfg.AttrDisplayName == "" {
		cfg.AttrDisplayName = "cn"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: bad url: %w", err)
	}
	tlsConf := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // opt-in for labs only
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("ldap: read ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ldap: ca_cert_file contained no certificates")
		}
		tlsConf.RootCAs = pool
	}
	return &Client{cfg: cfg, tlsConf: tlsConf}, nil
}

// ID returns the connector identifier.
func (c *Client) ID() string { return connectorID }

// Login performs search-then-bind and returns the verified Identity. ok=false is
// returned for an unknown user or a wrong password; err is reserved for
// transport/configuration failures the operator must see.
func (c *Client) Login(ctx context.Context, username, password string) (authn.Identity, bool, error) {
	// Reject empty credentials: an empty password can yield an unauthenticated
	// bind that some servers accept as success.
	if username == "" || password == "" {
		return authn.Identity{}, false, nil
	}

	conn, err := c.dial()
	if err != nil {
		return authn.Identity{}, false, fmt.Errorf("ldap: connect: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(c.cfg.Timeout)

	// Bind as the service account (or anonymously) to search the directory.
	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return authn.Identity{}, false, fmt.Errorf("ldap: service bind: %w", err)
		}
	}

	entry, found, err := c.findUser(conn, username)
	if err != nil {
		return authn.Identity{}, false, err
	}
	if !found {
		return authn.Identity{}, false, nil // unknown or ambiguous ⇒ invalid
	}

	// Verify the password by binding as the resolved DN on a fresh connection,
	// so the service-account binding is never disturbed.
	userConn, err := c.dial()
	if err != nil {
		return authn.Identity{}, false, fmt.Errorf("ldap: connect (user): %w", err)
	}
	defer userConn.Close()
	userConn.SetTimeout(c.cfg.Timeout)
	if err := userConn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return authn.Identity{}, false, nil
		}
		return authn.Identity{}, false, fmt.Errorf("ldap: user bind: %w", err)
	}

	id := authn.Identity{
		Connector:   connectorID,
		ExternalID:  entry.DN,
		Username:    firstOr(entry.GetAttributeValue(c.cfg.AttrUsername), username),
		Email:       entry.GetAttributeValue(c.cfg.AttrEmail),
		DisplayName: entry.GetAttributeValue(c.cfg.AttrDisplayName),
		IsAdmin:     c.isAdmin(conn, entry.DN),
	}
	return id, true, nil
}

// findUser runs the user filter and returns the single matching entry. Zero or
// multiple matches ⇒ found=false (treated as invalid credentials by the caller).
func (c *Client) findUser(conn *goldap.Conn, username string) (*goldap.Entry, bool, error) {
	req := goldap.NewSearchRequest(
		c.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(c.cfg.Timeout.Seconds()), false,
		renderFilter(c.cfg.UserFilter, username),
		[]string{c.cfg.AttrUsername, c.cfg.AttrEmail, c.cfg.AttrDisplayName},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		// A size-limit-exceeded result means the filter is too broad — treat the
		// ambiguity as "no unique user" rather than a hard error.
		if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, false, nil
	}
	return res.Entries[0], true, nil
}

// isAdmin reports whether userDN is a member of the configured admin group. Any
// error or unset config ⇒ false (fail closed).
func (c *Client) isAdmin(conn *goldap.Conn, userDN string) bool {
	if c.cfg.AdminGroupDN == "" || c.cfg.GroupFilter == "" {
		return false
	}
	req := goldap.NewSearchRequest(
		c.cfg.AdminGroupDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		1, int(c.cfg.Timeout.Seconds()), false,
		renderFilter(c.cfg.GroupFilter, userDN), []string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return false
	}
	return len(res.Entries) == 1
}

// dial opens a connection, applying StartTLS when configured.
func (c *Client) dial() (*goldap.Conn, error) {
	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithTLSConfig(c.tlsConf))
	if err != nil {
		return nil, err
	}
	if c.cfg.StartTLS {
		if err := conn.StartTLS(c.tlsConf); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// renderFilter substitutes the single %s placeholder with an LDAP-escaped value,
// preventing filter injection.
func renderFilter(tmpl, value string) string {
	return strings.Replace(tmpl, "%s", goldap.EscapeFilter(value), 1)
}

func firstOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
