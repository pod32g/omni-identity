package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/store"
)

const (
	ensurePassword = "correct horse battery 9"
	ensureSecret   = "0123456789abcdef0123456789abcdef"
)

func ptr[T any](v T) *T { return &v }

func TestEnsureAdminCreatesOnceAndNeverTouchesAnExistingAccount(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	if !srv.needsSetup(ctx) {
		t.Fatal("a fresh server should need setup")
	}

	res, err := EnsureAdmin(ctx, srv.db, srv.cfg, AdminSpec{Username: "root", Email: "root@example.com", Password: ensurePassword})
	if err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if res.Result != EnsureCreated || res.UserID == "" {
		t.Fatalf("first call = %+v, want created", res)
	}
	// The running server sees it: the setup wizard is closed.
	if srv.needsSetup(ctx) {
		t.Error("setup wizard still open after admin ensure")
	}
	if rr := adminGet(srv, "/setup", ""); rr.Code != http.StatusSeeOther {
		t.Errorf("GET /setup = %d, want redirect to /login", rr.Code)
	}

	// A second call changes nothing — in particular not the password.
	again, err := EnsureAdmin(ctx, srv.db, srv.cfg, AdminSpec{Username: "root", Email: "root@example.com", Password: "a different password 1"})
	if err != nil {
		t.Fatalf("second EnsureAdmin: %v", err)
	}
	if again.Result != EnsureUnchanged || again.UserID != res.UserID {
		t.Errorf("second call = %+v, want unchanged for the same user", again)
	}
	u, _ := srv.db.GetUserByUsername(ctx, "root")
	if ok, _ := auth.VerifyPassword(ensurePassword, u.PasswordHash); !ok || !u.IsAdmin {
		t.Error("the original password must still be the one that works")
	}
	// An existing account needs no password at all.
	if _, err := EnsureAdmin(ctx, srv.db, srv.cfg, AdminSpec{Username: "root", Email: "root@example.com"}); err != nil {
		t.Errorf("ensure of an existing admin without a password: %v", err)
	}
}

func TestEnsureAdminRefusesToChangeWhoIsAnAdministrator(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	createUser(t, srv, "alice", "pw", false)
	off := createUser(t, srv, "bob", "pw", true)
	if err := srv.db.SetUserDisabled(ctx, off.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	cases := []struct {
		name string
		spec AdminSpec
		want string
	}{
		{"promote", AdminSpec{Username: "alice", Email: "alice@example.com", Password: ensurePassword}, "not an administrator"},
		{"re-enable", AdminSpec{Username: "bob", Email: "bob@example.com", Password: ensurePassword}, "disabled"},
		{"email taken", AdminSpec{Username: "carol", Email: "alice@example.com", Password: ensurePassword}, "already belongs"},
		{"no password", AdminSpec{Username: "carol", Email: "carol@example.com"}, "password is required"},
		{"no email", AdminSpec{Username: "carol", Password: ensurePassword}, "required"},
	}
	for _, tc := range cases {
		_, err := EnsureAdmin(ctx, srv.db, srv.cfg, tc.spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", tc.name, err, tc.want)
		}
	}
	if u, _ := srv.db.GetUserByUsername(ctx, "alice"); u.IsAdmin {
		t.Error("alice was promoted")
	}
	if _, err := srv.db.GetUserByUsername(ctx, "carol"); err == nil {
		t.Error("carol should not exist")
	}
}

// The password policy is the live one from the settings row, not the config.
func TestEnsureAdminAppliesTheLivePasswordPolicy(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	applySettings(t, srv, func(sv *SettingsView) { sv.RequireSymbol = true })

	_, err := EnsureAdmin(ctx, srv.db, srv.cfg, AdminSpec{Username: "root", Email: "root@example.com", Password: ensurePassword})
	if err == nil || !strings.Contains(err.Error(), "symbol") {
		t.Fatalf("err = %v, want the symbol requirement", err)
	}
	if _, err := EnsureAdmin(ctx, srv.db, srv.cfg, AdminSpec{Username: "root", Email: "root@example.com", Password: ensurePassword + "!"}); err != nil {
		t.Fatalf("compliant password refused: %v", err)
	}
}

func TestEnsureClientCreateUpdateAndLeaveAlone(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	spec := ClientSpec{
		ClientID:     "omni-access",
		Name:         ptr("Omni Access"),
		RedirectURIs: []string{"https://access.example.com/auth/callback"},
		SkipConsent:  ptr(true),
		Secret:       ensureSecret,
	}

	res, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Result != EnsureCreated || res.ClientSecret != "" {
		t.Fatalf("create = %+v, want created with no secret echoed back", res)
	}
	c, _ := srv.db.GetClient(ctx, "omni-access")
	if c.Type != "confidential" || !c.SkipConsent || !slices.Equal(c.AllowedScopes, defaultEnsureScopes) {
		t.Errorf("created client = %+v", c)
	}
	// The secret works at the token endpoint of the running server.
	rr := do(srv, tokenPost(url.Values{"grant_type": {"client_credentials"}, "client_id": {"omni-access"}, "client_secret": {ensureSecret}}))
	if rr.Code != http.StatusOK {
		t.Fatalf("token with the ensured secret = %d: %s", rr.Code, rr.Body.String())
	}

	if again, _ := EnsureClient(ctx, srv.db, srv.cfg, spec); again == nil || again.Result != EnsureUnchanged || len(again.Changed) != 0 {
		t.Errorf("identical call = %+v, want unchanged", again)
	}

	// Something set in the admin UI that the caller does not mention survives.
	c.DisplayName = "Access (set in the UI)"
	if err := srv.db.UpdateClient(ctx, c); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	spec.RedirectURIs = []string{"https://access.example.com/auth/callback", "https://access2.example.com/auth/callback"}
	upd, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Result != EnsureUpdated || !slices.Equal(upd.Changed, []string{"redirect_uris"}) {
		t.Errorf("update = %+v, want updated [redirect_uris]", upd)
	}
	c, _ = srv.db.GetClient(ctx, "omni-access")
	if c.DisplayName != "Access (set in the UI)" || len(c.RedirectURIs) != 2 {
		t.Errorf("after update = %+v", c)
	}

	// A different secret is a rotation: the old one stops working.
	spec.Secret = strings.Repeat("z", minClientSecretLen)
	rot, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if err != nil || rot.Result != EnsureUpdated || !slices.Equal(rot.Changed, []string{"secret"}) {
		t.Fatalf("rotate = %+v, %v", rot, err)
	}
	rr = do(srv, tokenPost(url.Values{"grant_type": {"client_credentials"}, "client_id": {"omni-access"}, "client_secret": {ensureSecret}}))
	if rr.Code == http.StatusOK {
		t.Error("the previous secret still works after rotation")
	}
}

func TestEnsureClientGeneratesASecretOnlyWhenItCreates(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	spec := ClientSpec{ClientID: "gen", Name: ptr("Generated"), RedirectURIs: []string{"https://gen.example.com/cb"}}

	res, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(res.ClientSecret) < minClientSecretLen {
		t.Fatalf("generated secret = %q", res.ClientSecret)
	}
	c, _ := srv.db.GetClient(ctx, "gen")
	if !auth.SecretMatches(res.ClientSecret, c.ClientSecretHash) {
		t.Error("the returned secret is not the stored one")
	}
	again, _ := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if again.ClientSecret != "" || again.Result != EnsureUnchanged {
		t.Errorf("second call = %+v, want unchanged and no secret", again)
	}
	out, _ := json.Marshal(again)
	if strings.Contains(string(out), "client_secret") {
		t.Errorf("JSON of an unchanged result mentions a secret: %s", out)
	}
}

func TestEnsureClientRefusals(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	base := func() ClientSpec {
		return ClientSpec{ClientID: "app", Name: ptr("App"), RedirectURIs: []string{"https://app.example.com/cb"}}
	}
	if _, err := EnsureClient(ctx, srv.db, srv.cfg, base()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := srv.db.SetClientDisabled(ctx, "app", true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ClientSpec)
		want   string
	}{
		{"bad id", func(s *ClientSpec) { s.ClientID = "has space" }, "client id"},
		{"short secret", func(s *ClientSpec) { s.Secret = "too-short" }, "at least"},
		{"type change", func(s *ClientSpec) { s.Type = ptr("public") }, "type can only be changed"},
		{"wildcard redirect", func(s *ClientSpec) { s.RedirectURIs = []string{"https://*.example.com/cb"} }, "Redirect URIs"},
		{"unknown scope", func(s *ClientSpec) { s.Scopes = []string{"openid", "everything"} }, "Unknown scope"},
		{"no redirect on create", func(s *ClientSpec) { s.ClientID, s.RedirectURIs = "other", nil }, "redirect URI is required"},
		{"secret for public", func(s *ClientSpec) { s.ClientID, s.Type, s.Secret = "pub", ptr("public"), ensureSecret }, "no secret"},
	}
	for _, tc := range cases {
		spec := base()
		tc.mutate(&spec)
		_, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", tc.name, err, tc.want)
		}
	}
	for _, id := range []string{"other", "pub"} {
		if _, err := srv.db.GetClient(ctx, id); err == nil {
			t.Errorf("client %q was created despite the refusal", id)
		}
	}

	// A disabled client is reported, updated, and stays disabled.
	spec := base()
	spec.Name = ptr("App renamed")
	res, err := EnsureClient(ctx, srv.db, srv.cfg, spec)
	if err != nil || !res.Disabled || res.Result != EnsureUpdated {
		t.Fatalf("ensure of a disabled client = %+v, %v", res, err)
	}
	if c, _ := srv.db.GetClient(ctx, "app"); !c.Disabled || c.Name != "App renamed" {
		t.Errorf("client = %+v, want renamed and still disabled", c)
	}
}

// The redirect policy is the live one: an http:// LAN callback is refused until
// the administrator allows private-network redirects, exactly as in the UI.
func TestEnsureClientAppliesTheLiveRedirectPolicy(t *testing.T) {
	srv := testServer(t)
	ctx := context.Background()
	spec := ClientSpec{ClientID: "lan", Name: ptr("LAN app"), RedirectURIs: []string{"http://access.omni.home.arpa/auth/callback"}}

	if _, err := EnsureClient(ctx, srv.db, srv.cfg, spec); err == nil {
		t.Fatal("private-network http redirect accepted with the policy off")
	}
	applySettings(t, srv, func(sv *SettingsView) { sv.AllowPrivateNetworkHTTPRedirect = true })
	if _, err := EnsureClient(ctx, srv.db, srv.cfg, spec); err != nil {
		t.Fatalf("policy on: %v", err)
	}
	spec.RedirectURIs = []string{"http://app.example.com/auth/callback"}
	if _, err := EnsureClient(ctx, srv.db, srv.cfg, spec); err == nil {
		t.Error("public http redirect accepted")
	}
}

func TestEnsureWritesAuditEventsAndDoesNotSeedSettings(t *testing.T) {
	// No server here: this is the command running before `serve` ever has.
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := testServer(t).cfg
	ctx := context.Background()

	if _, err := EnsureAdmin(ctx, db, cfg, AdminSpec{Username: "root", Email: "root@example.com", Password: ensurePassword}); err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if _, err := EnsureClient(ctx, db, cfg, ClientSpec{ClientID: "c1", Name: ptr("C1"),
		RedirectURIs: []string{"http://localhost:9000/cb"}, Secret: ensureSecret}); err != nil {
		t.Fatalf("EnsureClient (loopback allowed by config): %v", err)
	}

	if row, err := db.GetSettings(ctx); err != nil || row.Seeded {
		t.Errorf("settings row seeded = %v (err %v); the commands must leave seeding to serve", row != nil && row.Seeded, err)
	}
	events, err := db.ListAuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		if e.UserAgent != ensureActor {
			t.Errorf("event %s has user agent %q, want %q", e.Event, e.UserAgent, ensureActor)
		}
		seen[e.Event] = true
	}
	if !seen[evtUserCreated] || !seen[evtClientCreated] {
		t.Errorf("audit events = %v, want user and client creation", seen)
	}
}
