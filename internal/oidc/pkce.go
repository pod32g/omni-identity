package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE code challenge method we support.
const PKCEMethodS256 = "S256"

// ComputeS256Challenge returns base64url(SHA256(verifier)), per RFC 7636.
func ComputeS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE reports whether verifier satisfies challenge under the given
// method. Only S256 and plain are recognized; the authorize flow restricts new
// requests to S256.
func VerifyPKCE(verifier, challenge, method string) bool {
	switch method {
	case PKCEMethodS256:
		computed := ComputeS256Challenge(verifier)
		return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
	case "plain":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}
