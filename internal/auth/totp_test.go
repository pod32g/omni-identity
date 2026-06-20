package auth

import (
	"testing"
	"time"
)

// rfc6238Secret is "12345678901234567890" base32-encoded (the RFC 6238 SHA1
// test key).
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPCodeMatchesRFC6238(t *testing.T) {
	// RFC 6238 Appendix B (SHA1), truncated to 6 digits.
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := TOTPCode(rfc6238Secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("unix %d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("TOTPCode(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTPAcceptsSkewRejectsWrong(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_600_000_000, 0)
	code, _ := TOTPCode(secret, now)

	if !VerifyTOTP(secret, code, now) {
		t.Error("current code should verify")
	}
	// One step earlier still verifies (skew).
	if !VerifyTOTP(secret, code, now.Add(30*time.Second)) {
		t.Error("code should verify within +1 step skew")
	}
	// Far outside the window fails.
	if VerifyTOTP(secret, code, now.Add(5*time.Minute)) {
		t.Error("stale code should not verify")
	}
	if VerifyTOTP(secret, "000000", now) && code != "000000" {
		t.Error("wrong code should not verify")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("ABC", "Omni Identity", "alice@example.com")
	if uri == "" || uri[:10] != "otpauth://" {
		t.Errorf("unexpected provisioning URI: %s", uri)
	}
}
