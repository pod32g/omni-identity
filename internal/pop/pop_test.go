package pop

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RFC 7638 §3.1 example key and its thumbprint.
const rfc7638N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

func TestThumbprintMatchesRFC7638Vector(t *testing.T) {
	j, err := ParseJWK([]byte(`{"kty":"RSA","n":"` + rfc7638N + `","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := j.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint = %s", tp)
	}
}

func TestParseJWKRejectsPrivateMembers(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	j, _ := FromPublicKey(pub)
	b, _ := json.Marshal(j)
	leaked := strings.TrimSuffix(string(b), "}") + `,"d":"AAAA"}`
	if _, err := ParseJWK([]byte(leaked)); err != ErrPrivateKeyMaterial {
		t.Errorf("err = %v, want ErrPrivateKeyMaterial", err)
	}
}

func TestJWKRoundTripAllKeyTypes(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, tc := range []struct {
		name string
		pub  any
		alg  string
	}{
		{"ed25519", edPub, AlgEdDSA},
		{"p256", &ecKey.PublicKey, AlgES256},
		{"rsa", &rsaKey.PublicKey, AlgRS256},
	} {
		j, err := FromPublicKey(tc.pub)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		b, _ := json.Marshal(j)
		parsed, err := ParseJWK(b)
		if err != nil {
			t.Fatalf("%s parse: %v", tc.name, err)
		}
		if alg, _ := parsed.Algorithm(); alg != tc.alg {
			t.Errorf("%s alg = %s want %s", tc.name, alg, tc.alg)
		}
		t1, _ := j.Thumbprint()
		t2, _ := parsed.Thumbprint()
		if t1 != t2 || t1 == "" {
			t.Errorf("%s thumbprint mismatch", tc.name)
		}
		canon, _ := parsed.Canonical()
		if strings.Contains(canon, "alg") || strings.Contains(canon, " ") {
			t.Errorf("%s canonical form has extra members/whitespace: %s", tc.name, canon)
		}
	}
}

func TestJWKRejectsSmallRSAAndBadCurve(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := FromPublicKey(&small.PublicKey); err == nil {
		t.Error("1024-bit RSA accepted")
	}
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`)); err == nil {
		t.Error("P-384 accepted")
	}
	if _, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)); err == nil {
		t.Error("off-curve point accepted")
	}
}

func TestDPoPProofRoundTrip(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	raw, err := NewProof(key, "POST", "https://id.example/oauth2/token?x=1", "tok", now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyProof(raw, ProofOptions{Now: now, HTM: "POST", HTU: "https://ID.EXAMPLE/oauth2/token", AccessToken: "tok"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Alg != AlgEdDSA || p.JKT == "" || p.JTI == "" {
		t.Errorf("proof = %+v", p)
	}
	want, _ := (&JWK{}).Thumbprint() // sanity: empty key has no thumbprint
	if want != "" {
		t.Error("unexpected thumbprint for empty JWK")
	}

	cases := map[string]ProofOptions{
		"wrong method":      {Now: now, HTM: "GET", HTU: "https://id.example/oauth2/token"},
		"wrong path":        {Now: now, HTM: "POST", HTU: "https://id.example/oauth2/other"},
		"wrong host":        {Now: now, HTM: "POST", HTU: "https://evil.example/oauth2/token"},
		"wrong ath":         {Now: now, HTM: "POST", HTU: "https://id.example/oauth2/token", AccessToken: "other"},
		"iat too old":       {Now: now.Add(10 * time.Minute), HTM: "POST", HTU: "https://id.example/oauth2/token"},
		"iat in the future": {Now: now.Add(-10 * time.Minute), HTM: "POST", HTU: "https://id.example/oauth2/token"},
	}
	for name, opt := range cases {
		if _, err := VerifyProof(raw, opt); err == nil {
			t.Errorf("%s: proof accepted", name)
		}
	}
}

func TestDPoPProofRejectsWrongTypAndTamper(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	jwk, _ := FromPublicKey(key.Public())
	raw, _ := Sign(key, map[string]any{"typ": "JWT", "jwk": jwk},
		jwt.MapClaims{"jti": "a", "htm": "POST", "htu": "https://x/y", "iat": now.Unix()})
	if _, err := VerifyProof(raw, ProofOptions{HTM: "POST", HTU: "https://x/y"}); err == nil {
		t.Error("typ=JWT accepted")
	}
	good, _ := NewProof(key, "POST", "https://x/y", "", now)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2] + "AA"
	if _, err := VerifyProof(tampered, ProofOptions{HTM: "POST", HTU: "https://x/y"}); err == nil {
		t.Error("tampered signature accepted")
	}
}

func TestAssertionVerifyAndReject(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	raw, err := NewAssertion(key, "fp", "dev-1", "https://id.example", now, 2*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := UnverifiedIssuer(raw)
	if err != nil || iss != "dev-1" {
		t.Fatalf("issuer = %q err=%v", iss, err)
	}
	base := AssertionOptions{Key: key.Public(), Alg: AlgEdDSA, Audience: "https://id.example", Now: now}
	a, err := VerifyAssertion(raw, base)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if a.Subject != "dev-1" || a.KID != "fp" || a.JTI == "" {
		t.Errorf("assertion = %+v", a)
	}

	wrongKey := base
	wrongKey.Key = other.Public()
	wrongAud := base
	wrongAud.Audience = "https://other.example"
	wrongAlg := base
	wrongAlg.Alg = AlgES256
	expired := base
	expired.Now = now.Add(20 * time.Minute)
	for name, opt := range map[string]AssertionOptions{"wrong key": wrongKey, "wrong aud": wrongAud, "wrong alg": wrongAlg, "expired": expired} {
		if _, err := VerifyAssertion(raw, opt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Lifetime cap: a hand-built 1h assertion must be refused.
	long, _ := Sign(key, nil, jwt.MapClaims{"iss": "dev-1", "sub": "dev-1", "aud": "https://id.example",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": "x"})
	if _, err := VerifyAssertion(long, base); err == nil {
		t.Error("1h assertion accepted")
	}
	// alg=none must never verify.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "dev-1", "sub": "dev-1", "aud": "https://id.example",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "x"})
	noneRaw, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := VerifyAssertion(noneRaw, base); err == nil {
		t.Error("alg=none accepted")
	}
}

func TestJTIHashScopedToKey(t *testing.T) {
	if JTIHash("a", "x") == JTIHash("b", "x") {
		t.Error("jti hash must be scoped by key thumbprint")
	}
}
