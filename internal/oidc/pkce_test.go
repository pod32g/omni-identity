package oidc

import "testing"

// Vectors from RFC 7636 Appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestComputeS256ChallengeMatchesRFCVector(t *testing.T) {
	if got := ComputeS256Challenge(rfcVerifier); got != rfcChallenge {
		t.Errorf("challenge = %q, want %q", got, rfcChallenge)
	}
}

func TestVerifyPKCES256Valid(t *testing.T) {
	if !VerifyPKCE(rfcVerifier, rfcChallenge, "S256") {
		t.Error("valid S256 verifier should pass")
	}
}

func TestVerifyPKCES256Invalid(t *testing.T) {
	if VerifyPKCE("wrong-verifier", rfcChallenge, "S256") {
		t.Error("wrong verifier must fail")
	}
}

func TestVerifyPKCEUnknownMethodFails(t *testing.T) {
	if VerifyPKCE(rfcVerifier, rfcChallenge, "bogus") {
		t.Error("unknown method must fail")
	}
}
