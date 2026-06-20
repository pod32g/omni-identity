package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBrandingDefaultsAndUpdate(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	b, err := db.GetBranding(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if b.ProductName != "Omni Identity" {
		t.Errorf("default product name = %q", b.ProductName)
	}

	if err := db.UpdateBranding(ctx, &model.Branding{
		ProductName: "Acme", AccentColor: "#fff", FooterText: "f", BackgroundStyle: "bg",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := db.SetBrandingLogo(ctx, []byte("PNGDATA"), "image/png"); err != nil {
		t.Fatalf("set logo: %v", err)
	}
	b, _ = db.GetBranding(ctx)
	if b.ProductName != "Acme" || b.AccentColor != "#fff" || string(b.LogoBytes) != "PNGDATA" || b.LogoContentType != "image/png" {
		t.Errorf("branding not persisted: %+v", b)
	}
}

func TestAuthRequestRoundTripAndExpiry(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	live := &model.AuthRequest{
		ID: "live", ClientID: "c", RedirectURI: "https://x/cb", ResponseType: "code",
		Scope: "openid", State: "s", Nonce: "n", CodeChallenge: "ch", CodeChallengeMethod: "S256",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	expired := &model.AuthRequest{
		ID: "old", ClientID: "c", RedirectURI: "https://x/cb", ResponseType: "code",
		Scope: "openid", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	}
	for _, a := range []*model.AuthRequest{live, expired} {
		if err := db.CreateAuthRequest(ctx, a); err != nil {
			t.Fatalf("create %s: %v", a.ID, err)
		}
	}

	got, err := db.GetAuthRequest(ctx, "live")
	if err != nil || got.State != "s" || got.CodeChallenge != "ch" {
		t.Fatalf("live round-trip failed: %+v err=%v", got, err)
	}
	if _, err := db.GetAuthRequest(ctx, "old"); err == nil {
		t.Error("expired request should read as not found")
	}

	if err := db.DeleteAuthRequest(ctx, "live"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := db.GetAuthRequest(ctx, "live"); err == nil {
		t.Error("deleted request should be gone")
	}

	n, err := db.DeleteExpiredAuthRequests(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d expired rows, want 1", n)
	}
}

func TestClientMetadataRoundTrip(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	c := &model.Client{
		ClientID: "app", Name: "App", Type: model.ClientTypeConfidential,
		RedirectURIs:           []string{"https://app/cb"},
		AllowedScopes:          []string{"openid"},
		DisplayName:            "My App",
		LogoURL:                "https://app/logo.png",
		HomepageURL:            "https://app",
		PostLogoutRedirectURIs: []string{"https://app/bye"},
		SkipConsent:            true,
		CreatedAt:              now, UpdatedAt: now,
	}
	if err := db.CreateClient(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := db.GetClient(ctx, "app")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DisplayName != "My App" || got.LogoURL != "https://app/logo.png" ||
		got.HomepageURL != "https://app" || !got.SkipConsent ||
		len(got.PostLogoutRedirectURIs) != 1 || got.PostLogoutRedirectURIs[0] != "https://app/bye" {
		t.Errorf("client metadata not persisted: %+v", got)
	}

	got.SkipConsent = false
	got.DisplayName = "Renamed"
	if err := db.UpdateClient(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := db.GetClient(ctx, "app")
	if got2.SkipConsent || got2.DisplayName != "Renamed" {
		t.Errorf("client update not persisted: %+v", got2)
	}
}
