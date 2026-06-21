package store

import (
	"context"
	"testing"
)

func TestSettingsDefaultsAndUpdate(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	s, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	// Migration seeds sensible defaults with seeded=false.
	if s.TokenTTL != "15m" || s.PasswordMinLength != 12 || s.MaxFailedLogins != 5 ||
		s.RateLimitWindow != "15m" || s.LoginIPMaxAttempts != 20 ||
		s.PasswordVerifyConcurrency != 4 || !s.AllowLoopbackHTTPRedirect ||
		s.MaxLogoBytes != 512*1024 || !s.CookieSecure || s.Seeded {
		t.Fatalf("unexpected default settings: %+v", s)
	}

	s.Issuer = "https://id.test"
	s.TokenTTL = "10m"
	s.CookieSecure = false
	s.MaxFailedLogins = 3
	s.LoginIPMaxAttempts = 7
	s.AllowLoopbackHTTPRedirect = false
	if err := db.UpdateSettings(ctx, s); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	got, _ := db.GetSettings(ctx)
	if got.Issuer != "https://id.test" || got.TokenTTL != "10m" ||
		got.CookieSecure || got.MaxFailedLogins != 3 || got.LoginIPMaxAttempts != 7 ||
		got.AllowLoopbackHTTPRedirect || !got.Seeded {
		t.Errorf("settings not persisted / not marked seeded: %+v", got)
	}
}
