package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken returns a URL-safe, cryptographically random token encoding
// nBytes of entropy.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read never fails on supported platforms; panic if it does.
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
