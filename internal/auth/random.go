package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// RandomToken returns a URL-safe, cryptographically random token encoding
// nBytes of entropy.
func RandomToken(nBytes int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(nBytes))
}

// RandomHex returns a lowercase hex token encoding nBytes of entropy. Unlike
// RandomToken, its alphabet is case-insensitive and contains no "-"/"_", so it
// survives normalization losslessly (used for recovery codes).
func RandomHex(nBytes int) string {
	return hex.EncodeToString(randomBytes(nBytes))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read never fails on supported platforms; panic if it does.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return b
}
