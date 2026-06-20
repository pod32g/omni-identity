// Package config loads and validates Omni Identity configuration from a YAML
// file, applying defaults and environment-variable overrides.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the validated, runtime configuration.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Security SecurityConfig
	Cookies  CookieConfig
}

// ServerConfig holds HTTP listener settings.
type ServerConfig struct {
	Host      string
	Port      int
	PublicURL string
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
	// Password policy.
	PasswordMinLength int
	// SessionIdleTimeout expires idle sessions; 0 disables idle expiry (the
	// absolute session lifetime still applies).
	SessionIdleTimeout time.Duration
}

// CookieConfig holds browser cookie settings.
type CookieConfig struct {
	Secure bool
}

// fileConfig mirrors the on-disk YAML shape, where durations are strings.
type fileConfig struct {
	Server struct {
		Host      string `yaml:"host"`
		Port      int    `yaml:"port"`
		PublicURL string `yaml:"public_url"`
	} `yaml:"server"`
	Database struct {
		Driver string `yaml:"driver"`
		Path   string `yaml:"path"`
		URL    string `yaml:"url"`
	} `yaml:"database"`
	Security struct {
		Issuer             string `yaml:"issuer"`
		TokenTTL           string `yaml:"token_ttl"`
		RefreshTokenTTL    string `yaml:"refresh_token_ttl"`
		MaxFailedLogins    int    `yaml:"max_failed_logins"`
		LockoutDuration    string `yaml:"lockout_duration"`
		PasswordMinLength  int    `yaml:"password_min_length"`
		SessionIdleTimeout string `yaml:"session_idle_timeout"`
	} `yaml:"security"`
	Cookies struct {
		// Secure is a pointer so we can tell "unset" from "false".
		Secure *bool `yaml:"secure"`
	} `yaml:"cookies"`
}

const (
	defaultHost              = "0.0.0.0"
	defaultPort              = 8080
	defaultDBPath            = "./omni-identity.db"
	defaultTokenTTL          = 15 * time.Minute
	defaultRefreshTokenTTL   = 720 * time.Hour
	defaultMaxFailedLogins   = 5
	defaultLockoutDuration   = 15 * time.Minute
	defaultPasswordMinLength = 12
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
	cfg.Security.PasswordMinLength = orDefaultInt(fc.Security.PasswordMinLength, defaultPasswordMinLength)
	cfg.Security.SessionIdleTimeout, err = parseDurationOr(fc.Security.SessionIdleTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("security.session_idle_timeout: %w", err)
	}

	cfg.Cookies.Secure = true
	if fc.Cookies.Secure != nil {
		cfg.Cookies.Secure = *fc.Cookies.Secure
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Server.PublicURL == "" {
		return fmt.Errorf("server.public_url is required")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range", c.Server.Port)
	}
	if c.Security.Issuer == "" {
		return fmt.Errorf("security.issuer is required")
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
	return nil
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
	if v := os.Getenv("OMNI_SECURITY_PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			fc.Security.PasswordMinLength = n
		}
	}
	if v := os.Getenv("OMNI_SECURITY_SESSION_IDLE_TIMEOUT"); v != "" {
		fc.Security.SessionIdleTimeout = v
	}
	if v := os.Getenv("OMNI_COOKIES_SECURE"); v != "" {
		b := v == "true" || v == "1"
		fc.Cookies.Secure = &b
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
