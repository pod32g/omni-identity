package auth

import "testing"

func TestHashTokenIsDeterministicAndHidesInput(t *testing.T) {
	h1 := HashToken("secret-value")
	h2 := HashToken("secret-value")
	if h1 != h2 {
		t.Error("hashing the same token must be deterministic")
	}
	if h1 == "secret-value" || len(h1) != 64 {
		t.Errorf("unexpected hash %q", h1)
	}
	if HashToken("other") == h1 {
		t.Error("different inputs must hash differently")
	}
}

func TestSecretMatches(t *testing.T) {
	stored := HashToken("client-secret")
	if !SecretMatches("client-secret", stored) {
		t.Error("correct secret should match")
	}
	if SecretMatches("wrong", stored) {
		t.Error("wrong secret must not match")
	}
}
