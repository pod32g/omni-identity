// Package tokens manages JWT signing keys (RSA + Ed25519), the JWKS document,
// and (in later milestones) issuance and verification of JWTs.
package tokens

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

// Supported signing algorithms.
const (
	AlgRS256 = "RS256"
	AlgEdDSA = "EdDSA"
)

// SigningKeyStore is the persistence surface the KeyManager needs.
type SigningKeyStore interface {
	CreateSigningKey(ctx context.Context, k *model.SigningKey) error
	ListSigningKeys(ctx context.Context) ([]model.SigningKey, error)
	GetActiveSigningKey(ctx context.Context, alg string) (*model.SigningKey, error)
}

// Signer is an active signing key ready for use with a JWT library.
type Signer struct {
	KID string
	Alg string
	Key crypto.Signer // *rsa.PrivateKey or ed25519.PrivateKey
}

// KeyManager owns the loaded signing keys and the JWKS document.
type KeyManager struct {
	store     SigningKeyStore
	signers   map[string]*Signer        // alg -> active signer
	verifiers map[string]crypto.PublicKey // kid -> public key (all keys)
	jwks      []byte                     // pre-rendered JWKS for all public keys
}

// NewKeyManager ensures an active RS256 and EdDSA key exist (generating them on
// first run), then loads all keys into memory and renders the JWKS.
func NewKeyManager(ctx context.Context, s SigningKeyStore) (*KeyManager, error) {
	km := &KeyManager{
		store:     s,
		signers:   map[string]*Signer{},
		verifiers: map[string]crypto.PublicKey{},
	}

	for _, alg := range []string{AlgRS256, AlgEdDSA} {
		if _, err := s.GetActiveSigningKey(ctx, alg); errors.Is(err, store.ErrNotFound) {
			key, err := generateKey(alg)
			if err != nil {
				return nil, err
			}
			if err := s.CreateSigningKey(ctx, key); err != nil {
				return nil, fmt.Errorf("store %s key: %w", alg, err)
			}
		} else if err != nil {
			return nil, err
		}
	}

	if err := km.load(ctx); err != nil {
		return nil, err
	}
	return km, nil
}

// load reads every key, parses private material for active keys, and assembles
// the JWKS document from all public keys.
func (km *KeyManager) load(ctx context.Context) error {
	keys, err := km.store.ListSigningKeys(ctx)
	if err != nil {
		return err
	}

	jwkList := make([]json.RawMessage, 0, len(keys))
	for i := range keys {
		k := keys[i]
		jwkList = append(jwkList, json.RawMessage(k.PublicJWK))

		signer, err := parsePrivatePEM(k.PrivatePEM)
		if err != nil {
			return fmt.Errorf("parse key %s: %w", k.KID, err)
		}
		// Every key (active or rotated) can verify tokens it previously signed.
		km.verifiers[k.KID] = signer.Public()

		// Newest active key per alg becomes the signer (ListSigningKeys is newest-first).
		if k.Active {
			if _, exists := km.signers[k.Alg]; !exists {
				km.signers[k.Alg] = &Signer{KID: k.KID, Alg: k.Alg, Key: signer}
			}
		}
	}

	doc, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: jwkList})
	if err != nil {
		return err
	}
	km.jwks = doc
	return nil
}

// JWKS returns the JSON Web Key Set document (public keys only).
func (km *KeyManager) JWKS() []byte { return km.jwks }

// Signer returns the active signer for the given algorithm.
func (km *KeyManager) Signer(alg string) (*Signer, error) {
	s, ok := km.signers[alg]
	if !ok {
		return nil, fmt.Errorf("no active signer for alg %q", alg)
	}
	return s, nil
}

// DefaultSigner returns the default (RS256) signer.
func (km *KeyManager) DefaultSigner() *Signer { return km.signers[AlgRS256] }

// PublicKey returns the public key for the given kid, for JWT verification.
func (km *KeyManager) PublicKey(kid string) (crypto.PublicKey, bool) {
	k, ok := km.verifiers[kid]
	return k, ok
}

// --- key generation & encoding ---

func generateKey(alg string) (*model.SigningKey, error) {
	switch alg {
	case AlgRS256:
		return generateRSAKey()
	case AlgEdDSA:
		return generateEd25519Key()
	default:
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
}

func generateRSAKey() (*model.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := newKID()
	pemStr, err := marshalPKCS8PEM(priv)
	if err != nil {
		return nil, err
	}
	jwk := jwk{
		Kty: "RSA", Use: "sig", Alg: AlgRS256, Kid: kid,
		N: b64u(priv.PublicKey.N.Bytes()),
		E: b64u(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	return newSigningKeyModel(kid, AlgRS256, jwk, pemStr)
}

func generateEd25519Key() (*model.SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := newKID()
	pemStr, err := marshalPKCS8PEM(priv)
	if err != nil {
		return nil, err
	}
	jwk := jwk{
		Kty: "OKP", Use: "sig", Alg: AlgEdDSA, Kid: kid,
		Crv: "Ed25519", X: b64u(pub),
	}
	return newSigningKeyModel(kid, AlgEdDSA, jwk, pemStr)
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

func newSigningKeyModel(kid, alg string, j jwk, privatePEM string) (*model.SigningKey, error) {
	jwkJSON, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	return &model.SigningKey{
		KID:        kid,
		Alg:        alg,
		PublicJWK:  string(jwkJSON),
		PrivatePEM: privatePEM,
		Active:     true,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func marshalPKCS8PEM(key crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parsePrivatePEM(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T is not a crypto.Signer", parsed)
	}
	return signer, nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newKID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("tokens: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
