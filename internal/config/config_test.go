package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLDAPDisabledByDefault(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.Enabled {
		t.Fatal("LDAP should be off by default")
	}
}

func TestLDAPPresetActiveDirectory(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  preset: activedirectory\n"+
		"  url: ldaps://dc:636\n  base_dn: dc=x\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.UserFilter != "(&(objectClass=user)(sAMAccountName=%s))" {
		t.Errorf("AD user_filter = %q", cfg.LDAP.UserFilter)
	}
	if cfg.LDAP.AttrUsername != "sAMAccountName" || cfg.LDAP.AttrDisplayName != "displayName" {
		t.Errorf("AD attrs = %q / %q", cfg.LDAP.AttrUsername, cfg.LDAP.AttrDisplayName)
	}
	if cfg.LDAP.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v", cfg.LDAP.Timeout)
	}
}

func TestLDAPDefaultPresetIsOpenLDAP(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  url: ldap://h\n  base_dn: dc=x\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.UserFilter != "(&(objectClass=inetOrgPerson)(uid=%s))" || cfg.LDAP.AttrUsername != "uid" {
		t.Errorf("openldap default not applied: %+v", cfg.LDAP)
	}
}

func TestLDAPExplicitFilterOverridesPreset(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  preset: openldap\n  url: ldap://h\n"+
		"  base_dn: dc=x\n  user_filter: \"(cn=%s)\"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.UserFilter != "(cn=%s)" {
		t.Errorf("explicit filter should win: %q", cfg.LDAP.UserFilter)
	}
}

func TestLDAPEnabledRequiresURL(t *testing.T) {
	_, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  base_dn: dc=x\n"))
	if err == nil {
		t.Fatal("expected error for missing ldap.url")
	}
}

func TestLDAPManageRequiresBindDN(t *testing.T) {
	// manage_enabled without a privileged bind_dn must be rejected.
	_, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  url: ldap://h\n  base_dn: dc=x\n  manage_enabled: true\n"))
	if err == nil {
		t.Fatal("expected error for manage_enabled without bind_dn")
	}
}

func TestLDAPManageEnabledParses(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"ldap:\n  enabled: true\n  url: ldap://h\n  base_dn: dc=x\n"+
		"  bind_dn: cn=admin,dc=x\n  bind_password: s3cret\n  manage_enabled: true\n"+
		"  people_base_dn: ou=people,dc=x\n  rdn_attr: uid\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.LDAP.ManageEnabled || cfg.LDAP.PeopleBaseDN != "ou=people,dc=x" || cfg.LDAP.RDNAttr != "uid" {
		t.Fatalf("management fields not parsed: %+v", cfg.LDAP)
	}
}

func TestLoggingLevelAndHTTPDefaults(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default level = %q, want info", cfg.Logging.Level)
	}
	// Default must be the quiet mode so successful requests don't flood the logs.
	if cfg.Logging.HTTPRequests != "errors" {
		t.Errorf("default http_requests = %q, want errors", cfg.Logging.HTTPRequests)
	}
}

func TestLoggingLevelRejectsUnknown(t *testing.T) {
	_, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"logging:\n  level: chatty\n"))
	if err == nil {
		t.Fatal("expected error for an invalid logging.level")
	}
}

func TestLoggingHTTPRequestsRejectsUnknown(t *testing.T) {
	_, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"logging:\n  http_requests: sometimes\n"))
	if err == nil {
		t.Fatal("expected error for an invalid logging.http_requests")
	}
}

func TestLoggingLevelAndHTTPEnvOverride(t *testing.T) {
	t.Setenv("OMNI_LOG_LEVEL", "debug")
	t.Setenv("OMNI_LOG_HTTP_REQUESTS", "all")
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Level != "debug" || cfg.Logging.HTTPRequests != "all" {
		t.Fatalf("env override not applied: level=%q http=%q", cfg.Logging.Level, cfg.Logging.HTTPRequests)
	}
}

func TestLoggingDisabledByDefaultWithServiceDefault(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Enabled {
		t.Fatal("logging should be off by default")
	}
	if cfg.Logging.Service != "omni-identity" {
		t.Errorf("default service = %q", cfg.Logging.Service)
	}
}

func TestLoggingEnabledRequiresURLAndKey(t *testing.T) {
	_, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"+
		"logging:\n  enabled: true\n  url: http://omnilog:8080\n"))
	if err == nil {
		t.Fatal("expected error for missing logging.api_key")
	}
}

func TestLoggingEnvOverride(t *testing.T) {
	t.Setenv("OMNI_LOGGING_ENABLED", "true")
	t.Setenv("OMNI_LOGGING_URL", "http://omnilog:8080")
	t.Setenv("OMNI_LOGGING_API_KEY", "k-secret")
	t.Setenv("OMNI_LOGGING_SERVICE", "omni-identity")
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Logging.Enabled || cfg.Logging.URL != "http://omnilog:8080" || cfg.Logging.APIKey != "k-secret" {
		t.Fatalf("logging env override failed: %+v", cfg.Logging)
	}
}

func TestLDAPEnvOverride(t *testing.T) {
	t.Setenv("OMNI_LDAP_ENABLED", "true")
	t.Setenv("OMNI_LDAP_URL", "ldap://env-host:389")
	t.Setenv("OMNI_LDAP_BASE_DN", "dc=env")
	t.Setenv("OMNI_LDAP_BIND_PASSWORD", "envsecret")
	cfg, err := Load(writeTempConfig(t, "server:\n  public_url: https://id.example\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LDAP.URL != "ldap://env-host:389" || cfg.LDAP.BindPassword != "envsecret" || !cfg.LDAP.Enabled {
		t.Fatalf("env override failed: %+v", cfg.LDAP)
	}
}

func TestLoadParsesFullConfig(t *testing.T) {
	path := writeTempConfig(t, `
server:
  host: 127.0.0.1
  port: 9090
  public_url: https://identity.omni.local
  read_header_timeout: 5s
  max_header_bytes: 65536

database:
  path: /tmp/omni.db

security:
  issuer: https://identity.omni.local
  token_ttl: 15m
  refresh_token_ttl: 720h
  rate_limit_window: 10m
  login_ip_max_attempts: 9
  password_verify_concurrency: 3
  max_login_username_bytes: 256
  max_login_password_bytes: 2048
  allow_loopback_http_redirects: false
  require_upper: true
  require_number: false
  session_lifetime: 8h

uploads:
  max_logo_bytes: 65536
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.PublicURL != "https://identity.omni.local" {
		t.Errorf("public_url = %q", cfg.Server.PublicURL)
	}
	if cfg.Database.Path != "/tmp/omni.db" {
		t.Errorf("db path = %q", cfg.Database.Path)
	}
	if cfg.Security.Issuer != "https://identity.omni.local" {
		t.Errorf("issuer = %q", cfg.Security.Issuer)
	}
	if cfg.Security.TokenTTL != 15*time.Minute {
		t.Errorf("token_ttl = %v, want 15m", cfg.Security.TokenTTL)
	}
	if cfg.Security.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("refresh_token_ttl = %v, want 720h", cfg.Security.RefreshTokenTTL)
	}
	if cfg.Server.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("read_header_timeout = %v, want 5s", cfg.Server.ReadHeaderTimeout)
	}
	if cfg.Server.MaxHeaderBytes != 65536 {
		t.Errorf("max_header_bytes = %d, want 65536", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Security.RateLimitWindow != 10*time.Minute {
		t.Errorf("rate_limit_window = %v, want 10m", cfg.Security.RateLimitWindow)
	}
	if cfg.Security.LoginIPMaxAttempts != 9 {
		t.Errorf("login_ip_max_attempts = %d, want 9", cfg.Security.LoginIPMaxAttempts)
	}
	if cfg.Security.PasswordVerifyConcurrency != 3 {
		t.Errorf("password_verify_concurrency = %d, want 3", cfg.Security.PasswordVerifyConcurrency)
	}
	if cfg.Security.MaxLoginUsernameBytes != 256 || cfg.Security.MaxLoginPasswordBytes != 2048 {
		t.Errorf("login byte caps = %d/%d", cfg.Security.MaxLoginUsernameBytes, cfg.Security.MaxLoginPasswordBytes)
	}
	if cfg.Security.AllowLoopbackHTTPRedirect {
		t.Error("allow_loopback_http_redirects should parse false")
	}
	if !cfg.Security.RequireUpper || cfg.Security.RequireNumber {
		t.Errorf("password complexity flags = upper:%v number:%v", cfg.Security.RequireUpper, cfg.Security.RequireNumber)
	}
	if cfg.Security.SessionLifetime != 8*time.Hour {
		t.Errorf("session_lifetime = %v, want 8h", cfg.Security.SessionLifetime)
	}
	if cfg.Uploads.MaxLogoBytes != 65536 {
		t.Errorf("max_logo_bytes = %d, want 65536", cfg.Uploads.MaxLogoBytes)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("default port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Database.Path != "./omni-identity.db" {
		t.Errorf("default db path = %q", cfg.Database.Path)
	}
	if cfg.Security.TokenTTL != 15*time.Minute {
		t.Errorf("default token_ttl = %v, want 15m", cfg.Security.TokenTTL)
	}
	if cfg.Security.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("default refresh_token_ttl = %v, want 720h", cfg.Security.RefreshTokenTTL)
	}
	if !cfg.Cookies.Secure {
		t.Error("cookies.secure should default to true")
	}
	if cfg.Server.ReadHeaderTimeout != 10*time.Second || cfg.Server.MaxHeaderBytes != 1<<20 {
		t.Errorf("server resource defaults = %v / %d", cfg.Server.ReadHeaderTimeout, cfg.Server.MaxHeaderBytes)
	}
	if cfg.Security.RateLimitWindow != 15*time.Minute || cfg.Security.LoginIPMaxAttempts != 20 {
		t.Errorf("abuse defaults = %v / %d", cfg.Security.RateLimitWindow, cfg.Security.LoginIPMaxAttempts)
	}
	if !cfg.Security.AllowLoopbackHTTPRedirect {
		t.Error("loopback HTTP redirects should default to allowed")
	}
	if !cfg.Security.RequireNumber || cfg.Security.RequireUpper || cfg.Security.RequireLower || cfg.Security.RequireSymbol {
		t.Errorf("password complexity defaults = upper:%v lower:%v number:%v symbol:%v",
			cfg.Security.RequireUpper, cfg.Security.RequireLower, cfg.Security.RequireNumber, cfg.Security.RequireSymbol)
	}
	if cfg.Security.SessionLifetime != 12*time.Hour {
		t.Errorf("default session lifetime = %v, want 12h", cfg.Security.SessionLifetime)
	}
	if cfg.Uploads.MaxLogoBytes != 512*1024 {
		t.Errorf("default max logo bytes = %d", cfg.Uploads.MaxLogoBytes)
	}
}

func TestLoadIssuerDefaultsToPublicURL(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Security.Issuer != "https://id.example.com" {
		t.Errorf("issuer should default to public_url, got %q", cfg.Security.Issuer)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: 8080
  public_url: http://localhost:8080
database:
  path: ./a.db
`)
	t.Setenv("OMNI_SERVER_PORT", "7000")
	t.Setenv("OMNI_SERVER_MAX_HEADER_BYTES", "65536")
	t.Setenv("OMNI_DATABASE_PATH", "/data/omni.db")
	t.Setenv("OMNI_SECURITY_LOGIN_IP_MAX_ATTEMPTS", "11")
	t.Setenv("OMNI_SECURITY_ALLOW_LOOPBACK_HTTP_REDIRECTS", "false")
	t.Setenv("OMNI_SECURITY_REQUIRE_SYMBOL", "true")
	t.Setenv("OMNI_SECURITY_SESSION_LIFETIME", "6h")
	t.Setenv("OMNI_UPLOADS_MAX_LOGO_BYTES", "65536")
	t.Setenv("OMNI_COOKIES_SECURE", "false")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 7000 {
		t.Errorf("env port override = %d, want 7000", cfg.Server.Port)
	}
	if cfg.Database.Path != "/data/omni.db" {
		t.Errorf("env db path override = %q", cfg.Database.Path)
	}
	if cfg.Cookies.Secure {
		t.Error("env should override cookies.secure to false")
	}
	if cfg.Server.MaxHeaderBytes != 65536 {
		t.Errorf("env max header bytes = %d, want 65536", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Security.LoginIPMaxAttempts != 11 {
		t.Errorf("env login IP max attempts = %d, want 11", cfg.Security.LoginIPMaxAttempts)
	}
	if cfg.Security.AllowLoopbackHTTPRedirect {
		t.Error("env should override loopback HTTP redirect policy to false")
	}
	if !cfg.Security.RequireSymbol {
		t.Error("env should override require_symbol to true")
	}
	if cfg.Security.SessionLifetime != 6*time.Hour {
		t.Errorf("env session lifetime = %v, want 6h", cfg.Security.SessionLifetime)
	}
	if cfg.Uploads.MaxLogoBytes != 65536 {
		t.Errorf("env max logo bytes = %d, want 65536", cfg.Uploads.MaxLogoBytes)
	}
}

func TestLoadRejectsNonLocalHTTPByDefault(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: http://id.example.test:8081
cookies:
  secure: false
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected non-local http public_url to require an explicit insecure override")
	}
}

func TestLoadAllowsLoopbackHTTPWithInsecureCookies(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: http://localhost:8080/
cookies:
  secure: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.PublicURL != "http://localhost:8080" {
		t.Errorf("normalized public_url = %q", cfg.Server.PublicURL)
	}
}

func TestLoadAllowsExplicitInsecureHTTP(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: http://id.example.test:8081
  allow_insecure_http: true
cookies:
  secure: false
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load with explicit insecure override: %v", err)
	}
}

func TestLoadRejectsHTTPSWithInsecureCookies(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
cookies:
  secure: false
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected https public_url to require secure cookies")
	}
}

func TestLoadRejectsPublicURLWithCredentials(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://user:pass@id.example.com
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected public_url with credentials to be rejected")
	}
}

func TestLoadMissingFileUsesEnvAndDefaults(t *testing.T) {
	// In a container we drive config purely via env, with no file present.
	t.Setenv("OMNI_SERVER_PUBLIC_URL", "https://id.example.com")
	t.Setenv("OMNI_DATABASE_PATH", "/data/omni-identity.db")

	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load with missing file should succeed via env: %v", err)
	}
	if cfg.Server.PublicURL != "https://id.example.com" {
		t.Errorf("public_url = %q", cfg.Server.PublicURL)
	}
	if cfg.Database.Path != "/data/omni-identity.db" {
		t.Errorf("db path = %q", cfg.Database.Path)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("default port = %d", cfg.Server.Port)
	}
}

func TestLoadMissingFileWithoutPublicURLStillErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing file and no public_url should still fail validation")
	}
}

func TestLoadRejectsMissingPublicURL(t *testing.T) {
	path := writeTempConfig(t, `
server:
  port: 8080
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error when public_url is missing")
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
security:
  token_ttl: not-a-duration
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid duration")
	}
}
