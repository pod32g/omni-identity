// Package crypto provides authenticated symmetric encryption for protecting
// sensitive values (e.g. TOTP secrets) at rest.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// ErrInvalidKey is returned when a key is not KeySize bytes.
var ErrInvalidKey = errors.New("crypto: key must be 32 bytes")

// Encryptor performs AES-256-GCM encryption with a fixed key.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor builds an Encryptor from a 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

// GenerateKeyB64 returns a fresh random 32-byte key, base64 (std) encoded.
func GenerateKeyB64() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// NewEncryptorFromB64 builds an Encryptor from a base64-encoded key.
func NewEncryptorFromB64(keyB64 string) (*Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return NewEncryptor(key)
}

// Encrypt returns base64(nonce || ciphertext || tag) for plaintext.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("crypto: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plain, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
