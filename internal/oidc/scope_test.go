package oidc

import "testing"

func TestSplitScope(t *testing.T) {
	got := SplitScope("openid  email   profile")
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (%v)", len(got), got)
	}
}

func TestHasScope(t *testing.T) {
	if !HasScope("openid offline_access", "offline_access") {
		t.Error("should detect offline_access")
	}
	if HasScope("openid email", "profile") {
		t.Error("should not detect absent scope")
	}
}

func TestScopesSubset(t *testing.T) {
	allowed := []string{"openid", "email", "profile", "offline_access"}
	if !ScopesSubset([]string{"openid", "email"}, allowed) {
		t.Error("subset should be allowed")
	}
	if ScopesSubset([]string{"openid", "admin"}, allowed) {
		t.Error("unknown scope must be rejected")
	}
}
