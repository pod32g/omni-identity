package pop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProofType is the required JWT typ header of a DPoP proof (RFC 9449 §4.2).
const ProofType = "dpop+jwt"

// DefaultSkew bounds how far a proof's or assertion's iat may drift from the
// server clock.
const DefaultSkew = 5 * time.Minute

// Proof is a validated DPoP proof.
type Proof struct {
	JWK      *JWK
	JKT      string // RFC 7638 thumbprint of JWK
	Alg      string
	JTI      string
	HTM      string
	HTU      string
	ATH      string
	IssuedAt time.Time
}

// ProofOptions parameterizes VerifyProof.
type ProofOptions struct {
	Now  time.Time     // zero = time.Now()
	Skew time.Duration // zero = DefaultSkew
	HTM  string        // expected HTTP method
	HTU  string        // expected target URI (query/fragment ignored)
	// AccessToken, when non-empty, requires an ath claim equal to its SHA-256.
	AccessToken string
}

// VerifyProof parses and validates a DPoP proof JWT per RFC 9449 §4.3, except
// for jti uniqueness, which the caller enforces with JTIHash + storage.
func VerifyProof(raw string, opt ProofOptions) (*Proof, error) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opt.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	if raw == "" {
		return nil, errors.New("dpop: missing proof")
	}
	if len(raw) > 8192 {
		return nil, errors.New("dpop: proof too large")
	}

	var jwk *JWK
	claims := jwt.MapClaims{}
	tok, err := jwt.NewParser(
		jwt.WithValidMethods(AllowedAlgs),
		jwt.WithoutClaimsValidation(), // iat window is checked manually below
	).ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != ProofType {
			return nil, fmt.Errorf("typ must be %s", ProofType)
		}
		rawJWK, ok := t.Header["jwk"]
		if !ok {
			return nil, errors.New("missing jwk header")
		}
		b, err := json.Marshal(rawJWK)
		if err != nil {
			return nil, err
		}
		j, err := ParseJWK(b)
		if err != nil {
			return nil, err
		}
		alg, _ := j.Algorithm()
		if alg != t.Method.Alg() {
			return nil, fmt.Errorf("alg %s does not match jwk", t.Method.Alg())
		}
		jwk = j
		return j.PublicKey()
	})
	if err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}

	p := &Proof{JWK: jwk, Alg: tok.Method.Alg()}
	if p.JKT, err = jwk.Thumbprint(); err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	if p.JTI, _ = claims["jti"].(string); p.JTI == "" || len(p.JTI) > 256 {
		return nil, errors.New("dpop: missing or invalid jti")
	}
	if p.HTM, _ = claims["htm"].(string); p.HTM == "" {
		return nil, errors.New("dpop: missing htm")
	}
	if p.HTU, _ = claims["htu"].(string); p.HTU == "" {
		return nil, errors.New("dpop: missing htu")
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return nil, errors.New("dpop: missing iat")
	}
	p.IssuedAt = iat
	if iat.Before(now.Add(-skew)) || iat.After(now.Add(skew)) {
		return nil, errors.New("dpop: iat outside the acceptable window")
	}
	if opt.HTM != "" && p.HTM != opt.HTM {
		return nil, errors.New("dpop: htm mismatch")
	}
	if opt.HTU != "" && !sameHTU(p.HTU, opt.HTU) {
		return nil, errors.New("dpop: htu mismatch")
	}
	p.ATH, _ = claims["ath"].(string)
	if opt.AccessToken != "" {
		if p.ATH == "" || p.ATH != AccessTokenHash(opt.AccessToken) {
			return nil, errors.New("dpop: ath does not match the access token")
		}
	}
	return p, nil
}

// AccessTokenHash returns base64url(SHA-256(token)) — the DPoP ath value.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// JTIHash derives the storage key for a single-use identifier, scoped to the
// key that presented it so one client cannot burn another's identifiers.
func JTIHash(jkt, jti string) string {
	sum := sha256.Sum256([]byte(jkt + "\x00" + jti))
	return hex.EncodeToString(sum[:])
}

// sameHTU compares two target URIs per RFC 9449 §4.3: scheme and host
// case-insensitively, path exactly, ignoring query and fragment.
func sameHTU(got, want string) bool {
	g, err1 := url.Parse(got)
	w, err2 := url.Parse(want)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(g.Scheme, w.Scheme) &&
		strings.EqualFold(g.Host, w.Host) &&
		g.Path == w.Path
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	}
	return time.Time{}, false
}

// NewProof builds a DPoP proof for a request (client-side helper, also used by
// tests). accessToken may be empty (token-endpoint requests).
func NewProof(key crypto.Signer, htm, htu, accessToken string, now time.Time) (string, error) {
	jwk, err := FromPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"jti": randomID(),
		"htm": htm,
		"htu": htu,
		"iat": now.Unix(),
	}
	if accessToken != "" {
		claims["ath"] = AccessTokenHash(accessToken)
	}
	return Sign(key, map[string]any{"typ": ProofType, "jwk": jwk}, claims)
}
