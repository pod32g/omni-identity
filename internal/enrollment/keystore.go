// Package enrollment implements the omni-enrollment endpoint agent: device key
// management, the RFC 8628 + DPoP enrollment ceremony, RFC 7523 device
// authentication, key rotation, and the renewal daemon. It talks to Omni
// Identity only through standard OAuth endpoints plus the two device resources
// documented in docs/DEVICE-IDENTITY-ARCHITECTURE.md.
package enrollment

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pod32g/omni-identity/internal/pop"
)

// Signer is the device's private key. It is deliberately narrow so a
// hardware-backed implementation (TPM 2.0, Secure Enclave) can replace the
// file-based one without touching the protocol code: the protocol only ever
// needs signatures and the public JWK.
type Signer interface {
	crypto.Signer
	// Algorithm is the JWS alg the key signs with (EdDSA, ES256, RS256).
	Algorithm() string
	// JWK is the public key.
	JWK() *pop.JWK
	// Fingerprint is the RFC 7638 thumbprint of JWK.
	Fingerprint() string
}

// fileKey is a software Ed25519 key stored as PKCS#8 PEM with 0600 permissions
// in a 0700 directory. Threat assumptions: docs/DEVICE-THREAT-MODEL.md §4.9.
type fileKey struct {
	ed25519.PrivateKey
	jwk *pop.JWK
	fp  string
}

func (k *fileKey) Algorithm() string   { return pop.AlgEdDSA }
func (k *fileKey) JWK() *pop.JWK       { return k.jwk }
func (k *fileKey) Fingerprint() string { return k.fp }

const keyFileName = "device.key"

// ErrNoKey is returned by LoadKey when no key has been generated yet.
var ErrNoKey = errors.New("no device key found")

// GenerateKey creates a fresh Ed25519 key in dir (creating dir 0700), refusing
// to overwrite an existing key unless overwrite is set.
func GenerateKey(dir string, overwrite bool) (Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, keyFileName)
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("%s already exists (use rotate-key or unenroll first)", path)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKey(path, priv); err != nil {
		return nil, err
	}
	return wrapKey(priv)
}

// writeKey persists a private key atomically with 0600 permissions.
func writeKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadKey reads the device key from dir.
func LoadKey(dir string) (Signer, error) {
	path := filepath.Join(dir, keyFileName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o); refusing to use it", path, fi.Mode().Perm())
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("device key: invalid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("device key: unsupported key type %T", parsed)
	}
	return wrapKey(priv)
}

// NewEphemeralKey returns an in-memory key (used for rotation before the new
// key is committed to disk, and by tests).
func NewEphemeralKey() (Signer, ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	s, err := wrapKey(priv)
	return s, priv, err
}

// CommitKey replaces the on-disk key with priv (after a successful rotation).
func CommitKey(dir string, priv ed25519.PrivateKey) error {
	return writeKey(filepath.Join(dir, keyFileName), priv)
}

func wrapKey(priv ed25519.PrivateKey) (Signer, error) {
	jwk, err := pop.FromPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	fp, err := jwk.Thumbprint()
	if err != nil {
		return nil, err
	}
	return &fileKey{PrivateKey: priv, jwk: jwk, fp: fp}, nil
}
