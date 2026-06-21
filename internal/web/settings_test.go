package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// applySettings mutates the live settings via the store + reload (the real path).
func applySettings(t *testing.T, srv *Server, mutate func(*SettingsView)) {
	t.Helper()
	sv := srv.settings.Current()
	mutate(&sv)
	if err := srv.db.UpdateSettings(context.Background(), sv.toModel()); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	srv.settings.Reload(context.Background())
}

func TestSettingsLiveAppliesTokenTTL(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "svc", "secret", false,
		[]string{"https://svc.example.com/cb"}, []string{"openid", "email"})

	applySettings(t, srv, func(sv *SettingsView) { sv.TokenTTL = 5 * time.Minute })

	ccRR := do(srv, tokenPost(url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"secret"},
	}))
	var tok tokenResponse
	_ = json.Unmarshal(ccRR.Body.Bytes(), &tok)
	if tok.ExpiresIn != 300 {
		t.Errorf("expires_in = %d, want 300 (live token_ttl=5m)", tok.ExpiresIn)
	}
	// The signed token's exp must reflect the new TTL too.
	vt, err := srv.issuer.Verify(tok.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	exp, _ := vt.Claims["exp"].(float64)
	iat, _ := vt.Claims["iat"].(float64)
	if d := exp - iat; d < 290 || d > 310 {
		t.Errorf("token lifetime = %.0fs, want ~300", d)
	}
}

func TestSettingsLiveAppliesIssuer(t *testing.T) {
	srv := testServer(t)
	applySettings(t, srv, func(sv *SettingsView) { sv.Issuer = "https://id.acme.test" })

	rr := do(srv, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if !strings.Contains(rr.Body.String(), `"issuer":"https://id.acme.test"`) {
		t.Errorf("discovery did not reflect live issuer; body: %s", rr.Body.String())
	}
}

func TestSettingsLiveAppliesLockoutThreshold(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "correct-horse-1", true)
	applySettings(t, srv, func(sv *SettingsView) { sv.MaxFailedLogins = 2 })

	for i := 0; i < 2; i++ {
		req := postForm("/login", url.Values{"username": {"alice"}, "password": {"wrong"}, "csrf_token": {"tok"}}, "tok")
		req.RemoteAddr = "10.1.0." + string(rune('1'+i)) + ":1"
		do(srv, req)
	}
	// Locked after only 2 (live threshold), below the default of 5.
	req := postForm("/login", url.Values{"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"}}, "tok")
	req.RemoteAddr = "10.1.9.9:1"
	rr := do(srv, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429 (locked at live threshold 2)", rr.Code)
	}
}

func TestSettingsLiveAppliesLoginIPRateLimit(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)
	applySettings(t, srv, func(sv *SettingsView) {
		sv.LoginIPMaxAttempts = 1
		sv.RateLimitWindow = time.Minute
	})

	for i := 0; i < 2; i++ {
		req := postForm("/login", url.Values{
			"username": {"rotated-" + string(rune('a'+i))}, "password": {"wrong"}, "csrf_token": {"tok"},
		}, "tok")
		req.RemoteAddr = "203.0.113.20:1234"
		rr := do(srv, req)
		if i == 1 && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("second rotated login code = %d, want 429", rr.Code)
		}
	}
}

func TestSettingsLiveAppliesRedirectPolicy(t *testing.T) {
	srv := testServer(t)
	applySettings(t, srv, func(sv *SettingsView) { sv.AllowLoopbackHTTPRedirect = false })
	sid := adminSession(t, srv)
	rr := adminPost(srv, "/admin/clients", url.Values{
		"name":          {"Native"},
		"client_id":     {"native-no-http"},
		"type":          {"public"},
		"redirect_uris": {"http://127.0.0.1:53682/callback"},
		"scopes":        {"openid"},
	}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 when loopback HTTP redirects are disabled", rr.Code)
	}
}

func TestSettingsLiveAppliesLogoSizeLimit(t *testing.T) {
	srv := testServer(t)
	applySettings(t, srv, func(sv *SettingsView) { sv.MaxLogoBytes = 16 * 1024 })
	sid := adminSession(t, srv)

	oversize := bytes.Repeat([]byte{'x'}, 16*1024+1)
	rr := adminUploadLogo(srv, sid, "logo.png", "image/png", oversize)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for live logo size limit", rr.Code)
	}
}

func TestSettingsLiveAppliesCookieSecure(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "correct-horse-1", true)
	applySettings(t, srv, func(sv *SettingsView) {
		sv.Issuer = "https://id.test"
		sv.PublicURL = "https://id.test"
		sv.CookieSecure = true
	})

	rr := do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok"))
	var secure bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "omni_session" {
			secure = c.Secure
		}
	}
	if !secure {
		t.Error("session cookie should be Secure when cookie_secure is enabled live")
	}
}

func TestAdminUpdateSettingsValidation(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)

	base := func() url.Values {
		return url.Values{
			"csrf_token":                    {"tok"},
			"issuer":                        {"https://id.test"},
			"public_url":                    {"https://id.test"},
			"cookie_secure":                 {"on"},
			"token_ttl":                     {"15m"},
			"refresh_token_ttl":             {"720h"},
			"rate_limit_window":             {"15m"},
			"login_ip_max_attempts":         {"20"},
			"password_verify_concurrency":   {"4"},
			"max_login_username_bytes":      {"320"},
			"max_login_password_bytes":      {"1024"},
			"allow_loopback_http_redirects": {"on"},
			"lockout_duration":              {"15m"},
			"session_lifetime":              {"12h"},
			"session_idle_timeout":          {"0"},
			"max_failed_logins":             {"5"},
			"password_min_length":           {"12"},
			"max_logo_kib":                  {"512"},
		}
	}

	// Password floor.
	bad := base()
	bad.Set("password_min_length", "4")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("password floor: code = %d, want 400", rr.Code)
	}
	// Refresh < access.
	bad = base()
	bad.Set("refresh_token_ttl", "1m")
	bad.Set("token_ttl", "15m")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("refresh<access: code = %d, want 400", rr.Code)
	}
	// Unparseable duration.
	bad = base()
	bad.Set("token_ttl", "soon")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("bad duration: code = %d, want 400", rr.Code)
	}
	// Invalid abuse-control bounds.
	bad = base()
	bad.Set("password_verify_concurrency", "0")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("bad concurrency: code = %d, want 400", rr.Code)
	}
	bad = base()
	bad.Set("max_logo_kib", "1")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("bad logo size: code = %d, want 400", rr.Code)
	}
	// Non-local HTTP issuer/public URL requires an explicit insecure override.
	bad = base()
	bad.Set("issuer", "http://id.example.test:8081")
	bad.Set("public_url", "http://id.example.test:8081")
	bad.Del("cookie_secure")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("non-local http URL: code = %d, want 400", rr.Code)
	}
	// HTTPS public URLs require Secure cookies.
	bad = base()
	bad.Del("cookie_secure")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("https without secure cookies: code = %d, want 400", rr.Code)
	}
	// Query strings and fragments are not valid OIDC issuer/public base URLs.
	bad = base()
	bad.Set("issuer", "https://id.test?debug=1")
	if rr := adminPost(srv, "/admin/settings/system", bad, sid); rr.Code != http.StatusBadRequest {
		t.Errorf("issuer with query: code = %d, want 400", rr.Code)
	}
	// Nothing persisted: defaults unchanged.
	if got := srv.settings.Current().PasswordMinLength; got != 12 {
		t.Errorf("settings mutated by rejected input: PasswordMinLength=%d", got)
	}

	// Valid update persists and applies live.
	good := base()
	good.Set("token_ttl", "10m")
	if rr := adminPost(srv, "/admin/settings/system", good, sid); rr.Code != http.StatusSeeOther {
		t.Fatalf("valid update: code = %d, want 303", rr.Code)
	}
	if srv.settings.Current().TokenTTL != 10*time.Minute {
		t.Errorf("token TTL not applied: %v", srv.settings.Current().TokenTTL)
	}
}

func TestAdminSettingsPageRenders(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	for _, want := range []string{"Account protection", `name="token_ttl"`, `name="login_ip_max_attempts"`, "Config/env status"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("settings page missing %q", want)
		}
	}
}
