// Package pop implements the proof-of-possession primitives used by enrolled
// devices: JSON Web Keys (RFC 7517) with RFC 7638 thumbprints, DPoP proofs
// (RFC 9449), and JWT authorization-grant assertions (RFC 7523). Everything is
// built on crypto/* and golang-jwt; no algorithms are invented here.
package pop

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWS algorithms accepted for device keys and DPoP proofs. EdDSA (Ed25519) is
// the default; ES256 and RS256 exist so hardware-backed keys can be used later.
const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
	AlgRS256 = "RS256"
)

// AllowedAlgs lists the algorithms VerifyProof/VerifyAssertion accept.
var AllowedAlgs = []string{AlgEdDSA, AlgES256, AlgRS256}

const minRSABits = 2048

// JWK is a public JSON Web Key. Private members are rejected on parse.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ErrPrivateKeyMaterial is returned when a JWK carries private members.
var ErrPrivateKeyMaterial = errors.New("jwk: contains private key material")

// ParseJWK decodes and validates a public JWK. It refuses any key carrying
// private members and any key type/curve outside the supported set.
func ParseJWK(raw []byte) (*JWK, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("jwk: %w", err)
	}
	for _, m := range privateMembers {
		if _, ok := members[m]; ok {
			return nil, ErrPrivateKeyMaterial
		}
	}
	var j JWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("jwk: %w", err)
	}
	if _, err := j.PublicKey(); err != nil {
		return nil, err
	}
	if _, err := j.Algorithm(); err != nil {
		return nil, err
	}
	return &j, nil
}

// FromPublicKey builds the JWK for an Ed25519, ECDSA P-256, or RSA public key.
func FromPublicKey(pub crypto.PublicKey) (*JWK, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(k), Alg: AlgEdDSA}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("jwk: unsupported curve %s", k.Curve.Params().Name)
		}
		return &JWK{
			Kty: "EC", Crv: "P-256", Alg: AlgES256,
			X: b64u(k.X.FillBytes(make([]byte, 32))),
			Y: b64u(k.Y.FillBytes(make([]byte, 32))),
		}, nil
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("jwk: RSA key must be at least %d bits", minRSABits)
		}
		return &JWK{
			Kty: "RSA", Alg: AlgRS256,
			N: b64u(k.N.Bytes()),
			E: b64u(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	default:
		return nil, fmt.Errorf("jwk: unsupported key type %T", pub)
	}
}

// PublicKey converts the JWK into a crypto.PublicKey, validating its shape.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwk: unsupported OKP curve %q", j.Crv)
		}
		x, err := b64d(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("jwk: invalid Ed25519 x")
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("jwk: unsupported EC curve %q", j.Crv)
		}
		x, errX := b64d(j.X)
		y, errY := b64d(j.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("jwk: invalid P-256 coordinates")
		}
		// Validate the point is on the curve via crypto/ecdh (rejects invalid
		// and identity points), then build the ecdsa key for verification.
		if _, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...)); err != nil {
			return nil, errors.New("jwk: point is not on P-256")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case "RSA":
		n, errN := b64d(j.N)
		e, errE := b64d(j.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("jwk: invalid RSA parameters")
		}
		N := new(big.Int).SetBytes(n)
		E := new(big.Int).SetBytes(e)
		if N.BitLen() < minRSABits {
			return nil, fmt.Errorf("jwk: RSA key must be at least %d bits", minRSABits)
		}
		if E.Cmp(big.NewInt(3)) < 0 || E.Bit(0) == 0 {
			return nil, errors.New("jwk: invalid RSA exponent")
		}
		return &rsa.PublicKey{N: N, E: int(E.Int64())}, nil
	default:
		return nil, fmt.Errorf("jwk: unsupported kty %q", j.Kty)
	}
}

// Algorithm returns the JWS algorithm implied by the key type. When the JWK
// carries an explicit alg it must agree.
func (j *JWK) Algorithm() (string, error) {
	var alg string
	switch j.Kty {
	case "OKP":
		alg = AlgEdDSA
	case "EC":
		alg = AlgES256
	case "RSA":
		alg = AlgRS256
	default:
		return "", fmt.Errorf("jwk: unsupported kty %q", j.Kty)
	}
	if j.Alg != "" && j.Alg != alg {
		return "", fmt.Errorf("jwk: alg %q does not match key type", j.Alg)
	}
	return alg, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint: base64url(SHA-256(canonical
// JSON of the required members, lexicographically ordered, no whitespace)).
func (j *JWK) Thumbprint() (string, error) {
	canon, err := j.canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return b64u(sum[:]), nil
}

// Canonical returns the storable public JWK: only the required members,
// in RFC 7638 order. This is what Omni persists in devices.public_key.
func (j *JWK) Canonical() (string, error) { return j.canonical() }

func (j *JWK) canonical() (string, error) {
	if _, err := j.PublicKey(); err != nil {
		return "", err
	}
	switch j.Kty {
	case "OKP":
		return fmt.Sprintf(`{"crv":%s,"kty":"OKP","x":%s}`, jstr(j.Crv), jstr(j.X)), nil
	case "EC":
		return fmt.Sprintf(`{"crv":%s,"kty":"EC","x":%s,"y":%s}`, jstr(j.Crv), jstr(j.X), jstr(j.Y)), nil
	case "RSA":
		return fmt.Sprintf(`{"e":%s,"kty":"RSA","n":%s}`, jstr(j.E), jstr(j.N)), nil
	}
	return "", fmt.Errorf("jwk: unsupported kty %q", j.Kty)
}

// SigningAlgorithm returns the JWS alg for a private key's public half.
func SigningAlgorithm(pub crypto.PublicKey) (string, error) {
	j, err := FromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return j.Algorithm()
}

func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
