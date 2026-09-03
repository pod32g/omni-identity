package pop

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MaxAssertionLifetime bounds exp - iat for device assertions.
const MaxAssertionLifetime = 5 * time.Minute

// Assertion is a validated RFC 7523 JWT signed by a device key.
type Assertion struct {
	Issuer    string
	Subject   string
	JTI       string
	KID       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Claims    jwt.MapClaims
}

// AssertionOptions parameterizes VerifyAssertion.
type AssertionOptions struct {
	Key         crypto.PublicKey // the device's registered public key
	Alg         string           // the device's registered algorithm
	Audience    string           // required aud value
	Now         time.Time        // zero = time.Now()
	Skew        time.Duration    // zero = DefaultSkew
	MaxLifetime time.Duration    // zero = MaxAssertionLifetime
}

// UnverifiedIssuer extracts the iss claim WITHOUT verifying the signature, so
// the caller can look up the issuing device's key. The result must never be
// trusted until VerifyAssertion succeeds with that key.
func UnverifiedIssuer(raw string) (string, error) {
	if raw == "" || len(raw) > 8192 {
		return "", errors.New("assertion: missing or oversized")
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", fmt.Errorf("assertion: %w", err)
	}
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return "", errors.New("assertion: missing iss")
	}
	return iss, nil
}

// VerifyAssertion validates signature, algorithm, audience, iat/exp, jti
// presence, and lifetime. jti uniqueness is the caller's responsibility.
func VerifyAssertion(raw string, opt AssertionOptions) (*Assertion, error) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opt.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	maxLife := opt.MaxLifetime
	if maxLife <= 0 {
		maxLife = MaxAssertionLifetime
	}
	if opt.Key == nil || opt.Alg == "" || opt.Audience == "" {
		return nil, errors.New("assertion: verifier misconfigured")
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{opt.Alg}),
		jwt.WithAudience(opt.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(skew),
		jwt.WithTimeFunc(func() time.Time { return now }),
	).ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return opt.Key, nil })
	if err != nil {
		return nil, fmt.Errorf("assertion: %w", err)
	}
	a := &Assertion{Claims: claims}
	a.KID, _ = tok.Header["kid"].(string)
	if a.Issuer, _ = claims["iss"].(string); a.Issuer == "" {
		return nil, errors.New("assertion: missing iss")
	}
	if a.Subject, _ = claims["sub"].(string); a.Subject == "" {
		return nil, errors.New("assertion: missing sub")
	}
	if a.JTI, _ = claims["jti"].(string); a.JTI == "" || len(a.JTI) > 256 {
		return nil, errors.New("assertion: missing or invalid jti")
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return nil, errors.New("assertion: missing iat")
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, errors.New("assertion: missing exp")
	}
	a.IssuedAt, a.ExpiresAt = iat, exp
	if exp.Sub(iat) > maxLife {
		return nil, fmt.Errorf("assertion: lifetime exceeds %s", maxLife)
	}
	return a, nil
}

// NewAssertion builds an RFC 7523 §2.1 authorization-grant assertion for a
// device: iss = sub = deviceID, aud = the issuer, short-lived, random jti.
func NewAssertion(key crypto.Signer, kid, deviceID, audience string, now time.Time, ttl time.Duration, extra map[string]any) (string, error) {
	if ttl <= 0 || ttl > MaxAssertionLifetime {
		ttl = MaxAssertionLifetime
	}
	claims := jwt.MapClaims{
		"iss": deviceID,
		"sub": deviceID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jti": randomID(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	header := map[string]any{}
	if kid != "" {
		header["kid"] = kid
	}
	return Sign(key, header, claims)
}

// Sign produces a compact JWS with the algorithm implied by the key's type.
// Ed25519 keys may be any crypto.Signer; ECDSA and RSA keys must be the
// standard library private key types (a hardware-backed implementation would
// register its own jwt.SigningMethod).
func Sign(key crypto.Signer, header map[string]any, claims jwt.MapClaims) (string, error) {
	alg, err := SigningAlgorithm(key.Public())
	if err != nil {
		return "", err
	}
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("pop: no signing method for %s", alg)
	}
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	return tok.SignedString(key)
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("pop: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
