package config

import "testing"

func TestPrivateNetworkHTTPRedirectsDefaultOff(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Security.AllowPrivateNetworkHTTPRedirect {
		t.Error("allow_private_network_http_redirects should default to false")
	}
}

func TestPrivateNetworkHTTPRedirectsParsesYAML(t *testing.T) {
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
security:
  allow_private_network_http_redirects: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.AllowPrivateNetworkHTTPRedirect {
		t.Error("allow_private_network_http_redirects should parse true")
	}
}

func TestPrivateNetworkHTTPRedirectsEnvOverride(t *testing.T) {
	t.Setenv("OMNI_SECURITY_ALLOW_PRIVATE_NETWORK_HTTP_REDIRECTS", "true")
	path := writeTempConfig(t, `
server:
  public_url: https://id.example.com
security:
  allow_private_network_http_redirects: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.AllowPrivateNetworkHTTPRedirect {
		t.Error("env should override allow_private_network_http_redirects to true")
	}
}
