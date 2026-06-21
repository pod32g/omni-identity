// Package config loads and validates Omni Identity configuration from a YAML
// file, applying defaults and environment-variable overrides.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the validated, runtime configuration.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Security SecurityConfig
	Cookies  CookieConfig
	Metrics  MetricsConfig
	Uploads  UploadsConfig
	SMTP     SMTPConfig
	LDAP     LDAPConfig
	Logging  LoggingConfig
}

// LoggingConfig configures optional shipping of structured logs to an external
// omnilog server (in addition to stdout). The API key is a secret and lives in
// config/env only. Validated only when Enabled is true.
type LoggingConfig struct {
	Enabled bool
	URL     string // omnilog base URL, e.g. http://host:8080
	APIKey  string
	Service string // source name reported to omnilog
}

// LDAPConfig configures the optional LDAP / Active Directory authentication
// backend (Omni acts as an LDAP client). It is validated only when Enabled is
// true. The bind password and TLS material are secrets and live here
// (config/env) only, never in the web-editable settings — matching SMTP.
//
// Preset ("openldap" or "activedirectory") fills in standard filters and
// attribute names; any field set explicitly overrides the preset.
type LDAPConfig struct {
	Enabled            bool
	Preset             string
	URL                string // ldap:// or ldaps://
	StartTLS           bool   // upgrade a ldap:// connection to TLS
	BindDN             string // service account for search; empty ⇒ anonymous
	BindPassword       string
	BaseDN             string
	UserFilter         string // %s = the escaped username
	AttrUsername       string
	AttrEmail          string
	AttrDisplayName    string
	AdminGroupDN       string // empty ⇒ no LDAP-granted admins
	GroupFilter        string // %s = the user DN
	CACertFile         string // PEM bundle for a private CA
	InsecureSkipVerify bool   // labs only
	Timeout            time.Duration
}

// SMTPConfig holds outbound email settings. Self-service password reset is
// enabled only when Host and From are set. Credentials live here (config/env),
// never in the web-editable settings.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

// Enabled reports whether outbound email is configured.
func (c SMTPConfig) Enabled() bool { return c.Host != "" && c.From != "" }

// ServerConfig holds HTTP listener settings.
type ServerConfig struct {
	Host              string
	Port              int
	PublicURL         string
	AllowInsecureHTTP bool
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// DatabaseConfig holds storage settings. Driver selects the backend
// ("sqlite" default, or "postgres"). Path is the SQLite file; URL is the
// Postgres connection string.
type DatabaseConfig struct {
	Driver string
	Path   string
	URL    string
}

// DSN returns the connection string for the configured driver.
func (c DatabaseConfig) DSN() string {
	if c.Driver == "postgres" {
		return c.URL
	}
	return c.Path
}

// SecurityConfig holds issuer, token lifetime, and account-protection settings.
type SecurityConfig struct {
	Issuer          string
	TokenTTL        time.Duration
	RefreshTokenTTL time.Duration
	// Account lockout.
	MaxFailedLogins int
	LockoutDuration time.Duration
	// Abuse controls.
	RateLimitWindow           time.Duration
	LoginIPMaxAttempts        int
	PasswordVerifyConcurrency int
	MaxLoginUsernameBytes     int
	MaxLoginPasswordBytes     int
	AllowLoopbackHTTPRedirect bool
	// Password policy.
	PasswordMinLength int
	RequireUpper      bool
	RequireLower      bool
	RequireNumber     bool
	RequireSymbol     bool
	// SessionLifetime is the absolute browser session lifetime.
	SessionLifetime time.Duration
	// SessionIdleTimeout expires idle sessions; 0 disables idle expiry (the
	// absolute session lifetime still applies).
	SessionIdleTimeout time.Duration
	// SetupToken is a one-time bootstrap secret required for first-run setup on
	// non-local public URLs.
	SetupToken string
}

// CookieConfig holds browser cookie settings.
type CookieConfig struct {
	Secure bool
}

// MetricsConfig holds the scrape token for Prometheus-style metrics. An empty
// token disables /metrics so deployments do not expose operational counters by
// default.
type MetricsConfig struct {
	BearerToken string
}

// UploadsConfig holds upload size limits. Values are intentionally config/env
// seed data for the live settings row, not secrets.
type UploadsConfig struct {
	MaxLogoBytes int
}

// fileConfig mirrors the on-disk YAML shape, where durations are strings.
type fileConfig struct {
	Server struct {
		Host              string `yaml:"host"`
		Port              int    `yaml:"port"`
		PublicURL         string `yaml:"public_url"`
		AllowInsecureHTTP *bool  `yaml:"allow_insecure_http"`
		ReadHeaderTimeout string `yaml:"read_header_timeout"`
		ReadTimeout       string `yaml:"read_timeout"`
		WriteTimeout      string `yaml:"write_timeout"`
		IdleTimeout       string `yaml:"idle_timeout"`
		MaxHeaderBytes    int    `yaml:"max_header_bytes"`
	} `yaml:"server"`
	Database struct {
		Driver string `yaml:"driver"`
		Path   string `yaml:"path"`
		URL    string `yaml:"url"`
	} `yaml:"database"`
	Security struct {
		Issuer                    string `yaml:"issuer"`
		TokenTTL                  string `yaml:"token_ttl"`
		RefreshTokenTTL           string `yaml:"refresh_token_ttl"`
		MaxFailedLogins           int    `yaml:"max_failed_logins"`
		LockoutDuration           string `yaml:"lockout_duration"`
		RateLimitWindow           string `yaml:"rate_limit_window"`
		LoginIPMaxAttempts        int    `yaml:"login_ip_max_attempts"`
		PasswordVerifyConcurrency int    `yaml:"password_verify_concurrency"`
		MaxLoginUsernameBytes     int    `yaml:"max_login_username_bytes"`
		MaxLoginPasswordBytes     int    `yaml:"max_login_password_bytes"`
		AllowLoopbackHTTPRedirect *bool  `yaml:"allow_loopback_http_redirects"`
		PasswordMinLength         int    `yaml:"password_min_length"`
		RequireUpper              *bool  `yaml:"require_upper"`
		RequireLower              *bool  `yaml:"require_lower"`
		RequireNumber             *bool  `yaml:"require_number"`
		RequireSymbol             *bool  `yaml:"require_symbol"`
		SessionLifetime           string `yaml:"session_lifetime"`
		SessionIdleTimeout        string `yaml:"session_idle_timeout"`
		SetupToken                string `yaml:"setup_token"`
	} `yaml:"security"`
	Cookies struct {
		// Secure is a pointer so we can tell "unset" from "false".
		Secure *bool `yaml:"secure"`
	} `yaml:"cookies"`
	Metrics struct {
		BearerToken string `yaml:"bearer_token"`
	} `yaml:"metrics"`
	Uploads struct {
		MaxLogoBytes int `yaml:"max_logo_bytes"`
	} `yaml:"uploads"`
	SMTP struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		From     string `yaml:"from"`
		StartTLS *bool  `yaml:"starttls"`
	} `yaml:"smtp"`
	LDAP struct {
		Enabled            bool   `yaml:"enabled"`
		Preset             string `yaml:"preset"`
		URL                string `yaml:"url"`
		StartTLS           bool   `yaml:"start_tls"`
		BindDN             string `yaml:"bind_dn"`
		BindPassword       string `yaml:"bind_password"`
		BaseDN             string `yaml:"base_dn"`
		UserFilter         string `yaml:"user_filter"`
		AttrUsername       string `yaml:"attr_username"`
		AttrEmail          string `yaml:"attr_email"`
		AttrDisplayName    string `yaml:"attr_display_name"`
		AdminGroupDN       string `yaml:"admin_group_dn"`
		GroupFilter        string `yaml:"group_filter"`
		CACertFile         string `yaml:"ca_cert_file"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
		Timeout            string `yaml:"timeout"`
	} `yaml:"ldap"`
	Logging struct {
		Enabled bool   `yaml:"enabled"`
		URL     string `yaml:"url"`
		APIKey  string `yaml:"api_key"`
		Service string `yaml:"service"`
	} `yaml:"logging"`
}

const (
	defaultHost                      = "0.0.0.0"
	defaultPort                      = 8080
	defaultDBPath                    = "./omni-identity.db"
	defaultReadHeaderTimeout         = 10 * time.Second
	defaultReadTimeout               = 30 * time.Second
	defaultWriteTimeout              = 30 * time.Second
	defaultIdleTimeout               = 120 * time.Second
	defaultMaxHeaderBytes            = 1 << 20
	defaultTokenTTL                  = 15 * time.Minute
	defaultRefreshTokenTTL           = 720 * time.Hour
	defaultMaxFailedLogins           = 5
	defaultLockoutDuration           = 15 * time.Minute
	defaultRateLimitWindow           = 15 * time.Minute
	defaultLoginIPMaxAttempts        = 20
	defaultPasswordVerifyConcurrency = 4
	defaultMaxLoginUsernameBytes     = 320
	defaultMaxLoginPasswordBytes     = 1024
	defaultPasswordMinLength         = 12
	defaultSessionLifetime           = 12 * time.Hour
	defaultMaxLogoBytes              = 512 * 1024
)

// Load reads, defaults, env-overrides, and validates the config at path. A
// missing file is not an error: configuration then comes from environment
// variables and defaults (useful for containerized, env-only deployments).
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var fc fileConfig
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &fc); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(&fc)

	cfg := &Config{}
	cfg.Server.Host = orDefault(fc.Server.Host, defaultHost)
	cfg.Server.Port = orDefaultInt(fc.Server.Port, defaultPort)
	cfg.Server.PublicURL = fc.Server.PublicURL
	if fc.Server.AllowInsecureHTTP != nil {
		cfg.Server.AllowInsecureHTTP = *fc.Server.AllowInsecureHTTP
	}
	cfg.Server.ReadHeaderTimeout, err = parseDurationOr(fc.Server.ReadHeaderTimeout, defaultReadHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("server.read_header_timeout: %w", err)
	}
	cfg.Server.ReadTimeout, err = parseDurationOr(fc.Server.ReadTimeout, defaultReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("server.read_timeout: %w", err)
	}
	cfg.Server.WriteTimeout, err = parseDurationOr(fc.Server.WriteTimeout, defaultWriteTimeout)
	if err != nil {
		return nil, fmt.Errorf("server.write_timeout: %w", err)
	}
	cfg.Server.IdleTimeout, err = parseDurationOr(fc.Server.IdleTimeout, defaultIdleTimeout)
	if err != nil {
		return nil, fmt.Errorf("server.idle_timeout: %w", err)
	}
	cfg.Server.MaxHeaderBytes = orDefaultInt(fc.Server.MaxHeaderBytes, defaultMaxHeaderBytes)
	cfg.Database.Driver = orDefault(fc.Database.Driver, "sqlite")
	cfg.Database.Path = orDefault(fc.Database.Path, defaultDBPath)
	cfg.Database.URL = fc.Database.URL
	cfg.Security.Issuer = orDefault(fc.Security.Issuer, fc.Server.PublicURL)

	cfg.Security.TokenTTL, err = parseDurationOr(fc.Security.TokenTTL, defaultTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("security.token_ttl: %w", err)
	}
	cfg.Security.RefreshTokenTTL, err = parseDurationOr(fc.Security.RefreshTokenTTL, defaultRefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("security.refresh_token_ttl: %w", err)
	}
	cfg.Security.MaxFailedLogins = orDefaultInt(fc.Security.MaxFailedLogins, defaultMaxFailedLogins)
	cfg.Security.LockoutDuration, err = parseDurationOr(fc.Security.LockoutDuration, defaultLockoutDuration)
	if err != nil {
		return nil, fmt.Errorf("security.lockout_duration: %w", err)
	}
	cfg.Security.RateLimitWindow, err = parseDurationOr(fc.Security.RateLimitWindow, defaultRateLimitWindow)
	if err != nil {
		return nil, fmt.Errorf("security.rate_limit_window: %w", err)
	}
	cfg.Security.LoginIPMaxAttempts = orDefaultInt(fc.Security.LoginIPMaxAttempts, defaultLoginIPMaxAttempts)
	cfg.Security.PasswordVerifyConcurrency = orDefaultInt(fc.Security.PasswordVerifyConcurrency, defaultPasswordVerifyConcurrency)
	cfg.Security.MaxLoginUsernameBytes = orDefaultInt(fc.Security.MaxLoginUsernameBytes, defaultMaxLoginUsernameBytes)
	cfg.Security.MaxLoginPasswordBytes = orDefaultInt(fc.Security.MaxLoginPasswordBytes, defaultMaxLoginPasswordBytes)
	cfg.Security.AllowLoopbackHTTPRedirect = true
	if fc.Security.AllowLoopbackHTTPRedirect != nil {
		cfg.Security.AllowLoopbackHTTPRedirect = *fc.Security.AllowLoopbackHTTPRedirect
	}
	cfg.Security.PasswordMinLength = orDefaultInt(fc.Security.PasswordMinLength, defaultPasswordMinLength)
	if fc.Security.RequireUpper != nil {
		cfg.Security.RequireUpper = *fc.Security.RequireUpper
	}
	if fc.Security.RequireLower != nil {
		cfg.Security.RequireLower = *fc.Security.RequireLower
	}
	cfg.Security.RequireNumber = true
	if fc.Security.RequireNumber != nil {
		cfg.Security.RequireNumber = *fc.Security.RequireNumber
	}
	if fc.Security.RequireSymbol != nil {
		cfg.Security.RequireSymbol = *fc.Security.RequireSymbol
	}
	cfg.Security.SessionLifetime, err = parseDurationOr(fc.Security.SessionLifetime, defaultSessionLifetime)
	if err != nil {
		return nil, fmt.Errorf("security.session_lifetime: %w", err)
	}
	cfg.Security.SessionIdleTimeout, err = parseDurationOr(fc.Security.SessionIdleTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("security.session_idle_timeout: %w", err)
	}
	cfg.Security.SetupToken = fc.Security.SetupToken

	cfg.Cookies.Secure = true
	if fc.Cookies.Secure != nil {
		cfg.Cookies.Secure = *fc.Cookies.Secure
	}
	cfg.Metrics.BearerToken = fc.Metrics.BearerToken
	cfg.Uploads.MaxLogoBytes = orDefaultInt(fc.Uploads.MaxLogoBytes, defaultMaxLogoBytes)

	cfg.SMTP.Host = fc.SMTP.Host
	cfg.SMTP.Port = orDefaultInt(fc.SMTP.Port, 587)
	cfg.SMTP.Username = fc.SMTP.Username
	cfg.SMTP.Password = fc.SMTP.Password
	cfg.SMTP.From = fc.SMTP.From
	cfg.SMTP.StartTLS = true
	if fc.SMTP.StartTLS != nil {
		cfg.SMTP.StartTLS = *fc.SMTP.StartTLS
	}

	cfg.LDAP.Enabled = fc.LDAP.Enabled
	cfg.LDAP.Preset = fc.LDAP.Preset
	cfg.LDAP.URL = fc.LDAP.URL
	cfg.LDAP.StartTLS = fc.LDAP.StartTLS
	cfg.LDAP.BindDN = fc.LDAP.BindDN
	cfg.LDAP.BindPassword = fc.LDAP.BindPassword
	cfg.LDAP.BaseDN = fc.LDAP.BaseDN
	cfg.LDAP.UserFilter = fc.LDAP.UserFilter
	cfg.LDAP.AttrUsername = fc.LDAP.AttrUsername
	cfg.LDAP.AttrEmail = fc.LDAP.AttrEmail
	cfg.LDAP.AttrDisplayName = fc.LDAP.AttrDisplayName
	cfg.LDAP.AdminGroupDN = fc.LDAP.AdminGroupDN
	cfg.LDAP.GroupFilter = fc.LDAP.GroupFilter
	cfg.LDAP.CACertFile = fc.LDAP.CACertFile
	cfg.LDAP.InsecureSkipVerify = fc.LDAP.InsecureSkipVerify
	cfg.LDAP.Timeout, err = parseDurationOr(fc.LDAP.Timeout, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ldap.timeout: %w", err)
	}
	applyLDAPPreset(&cfg.LDAP)

	cfg.Logging.Enabled = fc.Logging.Enabled
	cfg.Logging.URL = fc.Logging.URL
	cfg.Logging.APIKey = fc.Logging.APIKey
	cfg.Logging.Service = orDefault(fc.Logging.Service, "omni-identity")

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ldapPreset holds the standard filters/attributes for a directory flavor.
type ldapPreset struct {
	userFilter, attrUsername, attrEmail, attrDisplay, groupFilter string
}

// ldapPresets encodes the standard schemas so operators don't hand-write them.
var ldapPresets = map[string]ldapPreset{
	"openldap": {
		userFilter:   "(&(objectClass=inetOrgPerson)(uid=%s))",
		attrUsername: "uid", attrEmail: "mail", attrDisplay: "cn",
		groupFilter: "(&(objectClass=groupOfNames)(member=%s))",
	},
	"activedirectory": {
		userFilter:   "(&(objectClass=user)(sAMAccountName=%s))",
		attrUsername: "sAMAccountName", attrEmail: "mail", attrDisplay: "displayName",
		groupFilter: "(&(objectClass=group)(member=%s))",
	},
}

// applyLDAPPreset fills empty filter/attribute fields from the selected preset
// (default "openldap"). Explicit fields always win.
func applyLDAPPreset(c *LDAPConfig) {
	p, ok := ldapPresets[c.Preset]
	if !ok {
		p = ldapPresets["openldap"]
	}
	c.UserFilter = orDefault(c.UserFilter, p.userFilter)
	c.AttrUsername = orDefault(c.AttrUsername, p.attrUsername)
	c.AttrEmail = orDefault(c.AttrEmail, p.attrEmail)
	c.AttrDisplayName = orDefault(c.AttrDisplayName, p.attrDisplay)
	c.GroupFilter = orDefault(c.GroupFilter, p.groupFilter)
}

func (c *Config) validate() error {
	if c.Server.PublicURL == "" {
		return fmt.Errorf("server.public_url is required")
	}
	publicURL, parsedPublicURL, err := NormalizePublicURL("server.public_url", c.Server.PublicURL, c.Server.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	c.Server.PublicURL = publicURL
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range", c.Server.Port)
	}
	if c.Server.ReadHeaderTimeout <= 0 || c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 || c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server timeouts must be positive")
	}
	if c.Server.MaxHeaderBytes < 8*1024 || c.Server.MaxHeaderBytes > 16*1024*1024 {
		return fmt.Errorf("server.max_header_bytes must be between 8192 and 16777216")
	}
	if c.Security.Issuer == "" {
		return fmt.Errorf("security.issuer is required")
	}
	issuer, _, err := NormalizePublicURL("security.issuer", c.Security.Issuer, c.Server.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	c.Security.Issuer = issuer
	if parsedPublicURL.Scheme == "https" && !c.Cookies.Secure {
		return fmt.Errorf("cookies.secure must be true when server.public_url uses https")
	}
	if parsedPublicURL.Scheme == "http" && c.Cookies.Secure {
		return fmt.Errorf("cookies.secure must be false when server.public_url uses http")
	}
	if c.Security.TokenTTL <= 0 || c.Security.RefreshTokenTTL <= 0 {
		return fmt.Errorf("security token TTLs must be positive")
	}
	if c.Security.RefreshTokenTTL < c.Security.TokenTTL {
		return fmt.Errorf("security.refresh_token_ttl must be greater than or equal to security.token_ttl")
	}
	if c.Security.MaxFailedLogins < 1 {
		return fmt.Errorf("security.max_failed_logins must be at least 1")
	}
	if c.Security.LockoutDuration <= 0 {
		return fmt.Errorf("security.lockout_duration must be positive")
	}
	if c.Security.RateLimitWindow < time.Second || c.Security.RateLimitWindow > 24*time.Hour {
		return fmt.Errorf("security.rate_limit_window must be between 1s and 24h")
	}
	if c.Security.LoginIPMaxAttempts < 1 {
		return fmt.Errorf("security.login_ip_max_attempts must be at least 1")
	}
	if c.Security.PasswordVerifyConcurrency < 1 || c.Security.PasswordVerifyConcurrency > 64 {
		return fmt.Errorf("security.password_verify_concurrency must be between 1 and 64")
	}
	if c.Security.MaxLoginUsernameBytes < 64 || c.Security.MaxLoginUsernameBytes > 4096 {
		return fmt.Errorf("security.max_login_username_bytes must be between 64 and 4096")
	}
	if c.Security.MaxLoginPasswordBytes < 64 || c.Security.MaxLoginPasswordBytes > 1024*1024 {
		return fmt.Errorf("security.max_login_password_bytes must be between 64 and 1048576")
	}
	if c.Security.PasswordMinLength < 8 {
		return fmt.Errorf("security.password_min_length must be at least 8")
	}
	if c.Security.SessionLifetime <= 0 || c.Security.SessionLifetime > 90*24*time.Hour {
		return fmt.Errorf("security.session_lifetime must be between 1ns and 2160h")
	}
	if c.Security.SessionIdleTimeout < 0 || c.Security.SessionIdleTimeout > 90*24*time.Hour {
		return fmt.Errorf("security.session_idle_timeout must be between 0 and 2160h")
	}
	if c.Uploads.MaxLogoBytes < 16*1024 || c.Uploads.MaxLogoBytes > 5*1024*1024 {
		return fmt.Errorf("uploads.max_logo_bytes must be between 16384 and 5242880")
	}
	switch c.Database.Driver {
	case "sqlite":
		if c.Database.Path == "" {
			return fmt.Errorf("database.path is required for the sqlite driver")
		}
	case "postgres":
		if c.Database.URL == "" {
			return fmt.Errorf("database.url is required for the postgres driver")
		}
	default:
		return fmt.Errorf("database.driver %q is not supported (want sqlite or postgres)", c.Database.Driver)
	}
	if c.LDAP.Enabled {
		if c.LDAP.URL == "" {
			return fmt.Errorf("ldap.url is required when ldap.enabled")
		}
		if c.LDAP.BaseDN == "" {
			return fmt.Errorf("ldap.base_dn is required when ldap.enabled")
		}
		if !strings.Contains(c.LDAP.UserFilter, "%s") {
			return fmt.Errorf("ldap.user_filter must contain %%s (the username placeholder)")
		}
	}
	if c.Logging.Enabled {
		if c.Logging.URL == "" {
			return fmt.Errorf("logging.url is required when logging.enabled")
		}
		if c.Logging.APIKey == "" {
			return fmt.Errorf("logging.api_key is required when logging.enabled")
		}
	}
	return nil
}

// NormalizePublicURL validates and canonicalizes a public base URL used in
// issuer metadata and browser-facing redirects. Non-loopback http:// is refused
// unless explicitly allowed for development or tightly controlled private LANs.
func NormalizePublicURL(field, raw string, allowInsecureHTTP bool) (string, *url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("%s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", nil, fmt.Errorf("%s must be an absolute http(s) URL", field)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", nil, fmt.Errorf("%s must use http or https", field)
	}
	if u.User != nil {
		return "", nil, fmt.Errorf("%s must not include credentials", field)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", nil, fmt.Errorf("%s must not include query strings or fragments", field)
	}
	if u.Scheme == "http" && !isLoopbackURL(u) && !allowInsecureHTTP {
		return "", nil, fmt.Errorf("%s uses insecure http for non-local host %q; use https or set OMNI_ALLOW_INSECURE_HTTP=true only for development/private testing", field, u.Hostname())
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), u, nil
}

func isLoopbackURL(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func applyEnvOverrides(fc *fileConfig) {
	if v := os.Getenv("OMNI_SERVER_HOST"); v != "" {
		fc.Server.Host = v
	}
	if v := os.Getenv("OMNI_SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			fc.Server.Port = p
		}
	}
	if v := os.Getenv("OMNI_SERVER_PUBLIC_URL"); v != "" {
		fc.Server.PublicURL = v
	}
	if v := os.Getenv("OMNI_ALLOW_INSECURE_HTTP"); v != "" {
		b := v == "true" || v == "1"
		fc.Server.AllowInsecureHTTP = &b
	}
	if v := os.Getenv("OMNI_SERVER_READ_HEADER_TIMEOUT"); v != "" {
		fc.Server.ReadHeaderTimeout = v
	}
	if v := os.Getenv("OMNI_SERVER_READ_TIMEOUT"); v != "" {
		fc.Server.ReadTimeout = v
	}
	if v := os.Getenv("OMNI_SERVER_WRITE_TIMEOUT"); v != "" {
		fc.Server.WriteTimeout = v
	}
	if v := os.Getenv("OMNI_SERVER_IDLE_TIMEOUT"); v != "" {
		fc.Server.IdleTimeout = v
	}
	if v := os.Getenv("OMNI_SERVER_MAX_HEADER_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Server.MaxHeaderBytes = n
		}
	}
	if v := os.Getenv("OMNI_DATABASE_DRIVER"); v != "" {
		fc.Database.Driver = v
	}
	if v := os.Getenv("OMNI_DATABASE_PATH"); v != "" {
		fc.Database.Path = v
	}
	if v := os.Getenv("OMNI_DATABASE_URL"); v != "" {
		fc.Database.URL = v
	}
	if v := os.Getenv("OMNI_SECURITY_ISSUER"); v != "" {
		fc.Security.Issuer = v
	}
	if v := os.Getenv("OMNI_SECURITY_TOKEN_TTL"); v != "" {
		fc.Security.TokenTTL = v
	}
	if v := os.Getenv("OMNI_SECURITY_REFRESH_TOKEN_TTL"); v != "" {
		fc.Security.RefreshTokenTTL = v
	}
	if v := os.Getenv("OMNI_SECURITY_MAX_FAILED_LOGINS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.MaxFailedLogins = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_LOCKOUT_DURATION"); v != "" {
		fc.Security.LockoutDuration = v
	}
	if v := os.Getenv("OMNI_SECURITY_RATE_LIMIT_WINDOW"); v != "" {
		fc.Security.RateLimitWindow = v
	}
	if v := os.Getenv("OMNI_SECURITY_LOGIN_IP_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.LoginIPMaxAttempts = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_PASSWORD_VERIFY_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.PasswordVerifyConcurrency = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_MAX_LOGIN_USERNAME_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.MaxLoginUsernameBytes = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_MAX_LOGIN_PASSWORD_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.MaxLoginPasswordBytes = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_ALLOW_LOOPBACK_HTTP_REDIRECTS"); v != "" {
		b := v == "true" || v == "1"
		fc.Security.AllowLoopbackHTTPRedirect = &b
	}
	if v := os.Getenv("OMNI_SECURITY_PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.PasswordMinLength = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_REQUIRE_UPPER"); v != "" {
		b := v == "true" || v == "1"
		fc.Security.RequireUpper = &b
	}
	if v := os.Getenv("OMNI_SECURITY_REQUIRE_LOWER"); v != "" {
		b := v == "true" || v == "1"
		fc.Security.RequireLower = &b
	}
	if v := os.Getenv("OMNI_SECURITY_REQUIRE_NUMBER"); v != "" {
		b := v == "true" || v == "1"
		fc.Security.RequireNumber = &b
	}
	if v := os.Getenv("OMNI_SECURITY_REQUIRE_SYMBOL"); v != "" {
		b := v == "true" || v == "1"
		fc.Security.RequireSymbol = &b
	}
	if v := os.Getenv("OMNI_SECURITY_SESSION_LIFETIME"); v != "" {
		fc.Security.SessionLifetime = v
	}
	if v := os.Getenv("OMNI_SECURITY_SESSION_IDLE_TIMEOUT"); v != "" {
		fc.Security.SessionIdleTimeout = v
	}
	if v := os.Getenv("OMNI_SETUP_TOKEN"); v != "" {
		fc.Security.SetupToken = v
	}
	if v := os.Getenv("OMNI_COOKIES_SECURE"); v != "" {
		b := v == "true" || v == "1"
		fc.Cookies.Secure = &b
	}
	if v := os.Getenv("OMNI_METRICS_TOKEN"); v != "" {
		fc.Metrics.BearerToken = v
	}
	if v := os.Getenv("OMNI_UPLOADS_MAX_LOGO_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Uploads.MaxLogoBytes = n
		}
	}
	if v := os.Getenv("OMNI_SMTP_HOST"); v != "" {
		fc.SMTP.Host = v
	}
	if v := os.Getenv("OMNI_SMTP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			fc.SMTP.Port = p
		}
	}
	if v := os.Getenv("OMNI_SMTP_USERNAME"); v != "" {
		fc.SMTP.Username = v
	}
	if v := os.Getenv("OMNI_SMTP_PASSWORD"); v != "" {
		fc.SMTP.Password = v
	}
	if v := os.Getenv("OMNI_SMTP_FROM"); v != "" {
		fc.SMTP.From = v
	}
	if v := os.Getenv("OMNI_SMTP_STARTTLS"); v != "" {
		b := v == "true" || v == "1"
		fc.SMTP.StartTLS = &b
	}
	if v := os.Getenv("OMNI_LDAP_ENABLED"); v != "" {
		fc.LDAP.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("OMNI_LDAP_PRESET"); v != "" {
		fc.LDAP.Preset = v
	}
	if v := os.Getenv("OMNI_LDAP_URL"); v != "" {
		fc.LDAP.URL = v
	}
	if v := os.Getenv("OMNI_LDAP_START_TLS"); v != "" {
		fc.LDAP.StartTLS = v == "true" || v == "1"
	}
	if v := os.Getenv("OMNI_LDAP_BIND_DN"); v != "" {
		fc.LDAP.BindDN = v
	}
	if v := os.Getenv("OMNI_LDAP_BIND_PASSWORD"); v != "" {
		fc.LDAP.BindPassword = v
	}
	if v := os.Getenv("OMNI_LDAP_BASE_DN"); v != "" {
		fc.LDAP.BaseDN = v
	}
	if v := os.Getenv("OMNI_LDAP_USER_FILTER"); v != "" {
		fc.LDAP.UserFilter = v
	}
	if v := os.Getenv("OMNI_LDAP_ATTR_USERNAME"); v != "" {
		fc.LDAP.AttrUsername = v
	}
	if v := os.Getenv("OMNI_LDAP_ATTR_EMAIL"); v != "" {
		fc.LDAP.AttrEmail = v
	}
	if v := os.Getenv("OMNI_LDAP_ATTR_DISPLAY_NAME"); v != "" {
		fc.LDAP.AttrDisplayName = v
	}
	if v := os.Getenv("OMNI_LDAP_ADMIN_GROUP_DN"); v != "" {
		fc.LDAP.AdminGroupDN = v
	}
	if v := os.Getenv("OMNI_LDAP_GROUP_FILTER"); v != "" {
		fc.LDAP.GroupFilter = v
	}
	if v := os.Getenv("OMNI_LDAP_CA_CERT_FILE"); v != "" {
		fc.LDAP.CACertFile = v
	}
	if v := os.Getenv("OMNI_LDAP_INSECURE_SKIP_VERIFY"); v != "" {
		fc.LDAP.InsecureSkipVerify = v == "true" || v == "1"
	}
	if v := os.Getenv("OMNI_LDAP_TIMEOUT"); v != "" {
		fc.LDAP.Timeout = v
	}
	if v := os.Getenv("OMNI_LOGGING_ENABLED"); v != "" {
		fc.Logging.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("OMNI_LOGGING_URL"); v != "" {
		fc.Logging.URL = v
	}
	if v := os.Getenv("OMNI_LOGGING_API_KEY"); v != "" {
		fc.Logging.APIKey = v
	}
	if v := os.Getenv("OMNI_LOGGING_SERVICE"); v != "" {
		fc.Logging.Service = v
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func parseDurationOr(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	return d, nil
}
