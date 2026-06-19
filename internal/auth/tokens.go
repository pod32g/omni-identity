package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashToken returns the hex-encoded SHA-256 of a high-entropy token (auth codes,
// refresh tokens, client secrets). SHA-256 is appropriate here because these
// values are randomly generated; password hashing uses Argon2id instead.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SecretMatches reports whether a presented secret matches a stored SHA-256 hash,
// using a constant-time comparison.
func SecretMatches(presented, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashToken(presented)), []byte(storedHash)) == 1
}
