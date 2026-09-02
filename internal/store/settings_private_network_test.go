package store

import (
	"context"
	"testing"
)

func TestSettingsPrivateNetworkHTTPRedirectRoundTrip(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	s, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if s.AllowPrivateNetworkHTTPRedirect {
		t.Fatal("allow_private_network_http_redirects should default to false")
	}
	s.AllowPrivateNetworkHTTPRedirect = true
	if err := db.UpdateSettings(ctx, s); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	got, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !got.AllowPrivateNetworkHTTPRedirect {
		t.Error("allow_private_network_http_redirects not persisted")
	}
}
