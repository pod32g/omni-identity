package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238) — the de facto defaults that authenticator apps
// (Google Authenticator, Authy, 1Password, etc.) expect.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew allows the previous and next time-steps to absorb clock drift.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random base32 TOTP secret (160 bits).
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// TOTPCode computes the TOTP code for secret at time t.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(normalizeSecret(secret))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	return hotp(key, counter), nil
}

// VerifyTOTP reports whether code is valid for secret at time t, allowing one
// time-step of skew in each direction. The comparison is constant-time.
func VerifyTOTP(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := b32.DecodeString(normalizeSecret(secret))
	if err != nil {
		return false
	}
	base := int64(uint64(t.Unix()) / uint64(totpPeriod.Seconds()))
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want := hotp(key, uint64(base+d))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI builds an otpauth:// URI for QR/manual enrollment.
func TOTPProvisioningURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", normalizeSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + v.Encode()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%pow10(totpDigits))
}

func pow10(n int) uint32 {
	r := uint32(1)
	for i := 0; i < n; i++ {
		r *= 10
	}
	return r
}

func normalizeSecret(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}
