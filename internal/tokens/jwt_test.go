package tokens

import (
	"context"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	db := testStore(t)
	km, err := NewKeyManager(context.Background(), db)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return NewIssuer(km, "https://id.example.com", 15*time.Minute, 15*time.Minute)
}

func TestIssueAndVerifyAccessToken(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.IssueAccessToken("user-1", "jellyfin", "openid email")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	vt, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vt.Subject != "user-1" {
		t.Errorf("sub = %q, want user-1", vt.Subject)
	}
	if vt.Scope != "openid email" {
		t.Errorf("scope = %q", vt.Scope)
	}
	if !vt.IsAccessToken() {
		t.Error("expected token_use=access")
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	iss := testIssuer(t)
	tok, _ := iss.IssueAccessToken("user-1", "jellyfin", "openid")

	tampered := tok[:len(tok)-3] + "xxx"
	if _, err := iss.Verify(tampered); err == nil {
		t.Error("tampered token must not verify")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	iss := testIssuer(t)
	tok, _ := iss.IssueAccessToken("user-1", "jellyfin", "openid")

	other := NewIssuer(iss.km, "https://evil.example.com", time.Minute, time.Minute)
	if _, err := other.Verify(tok); err == nil {
		t.Error("token from a different issuer must not verify")
	}
}

func TestIDTokenContainsIdentityClaims(t *testing.T) {
	iss := testIssuer(t)
	p := Profile{
		Email:             "alice@example.com",
		EmailVerified:     true,
		PreferredUsername: "alice",
		Name:              "Alice A",
	}
	tok, err := iss.IssueIDToken("user-1", "jellyfin", p, "nonce-xyz", time.Now())
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	vt, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if vt.Audience != "jellyfin" {
		t.Errorf("aud = %q, want jellyfin", vt.Audience)
	}
	if vt.Email != "alice@example.com" {
		t.Errorf("email = %q", vt.Email)
	}
	if vt.PreferredUsername != "alice" {
		t.Errorf("preferred_username = %q", vt.PreferredUsername)
	}
	if vt.Claims["nonce"] != "nonce-xyz" {
		t.Errorf("nonce = %v", vt.Claims["nonce"])
	}
	if _, ok := vt.Claims["auth_time"]; !ok {
		t.Error("id token missing auth_time")
	}
}

func TestAccessTokenHasFutureExpiry(t *testing.T) {
	iss := testIssuer(t)
	tok, _ := iss.IssueAccessToken("user-1", "jellyfin", "openid")
	vt, err := iss.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	exp, ok := vt.Claims["exp"].(float64)
	if !ok {
		t.Fatal("exp missing")
	}
	if int64(exp) <= time.Now().Unix() {
		t.Error("access token already expired")
	}
}
