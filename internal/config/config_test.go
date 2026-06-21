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

database:
  path: /tmp/omni.db

security:
  issuer: https://identity.omni.local
  token_ttl: 15m
  refresh_token_ttl: 720h
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
  public_url: https://id.example.com
database:
  path: ./a.db
`)
	t.Setenv("OMNI_SERVER_PORT", "7000")
	t.Setenv("OMNI_DATABASE_PATH", "/data/omni.db")
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
