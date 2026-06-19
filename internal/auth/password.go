// Package auth provides password hashing, browser sessions, and CSRF support.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2Params controls the cost of Argon2id hashing.
type argon2Params struct {
	memory  uint32 // KiB
	time    uint32 // iterations
	threads uint8
	saltLen uint32
	keyLen  uint32
}

// defaultParams are tuned for an interactive login (64 MiB, 2 passes).
var defaultParams = argon2Params{
	memory:  64 * 1024,
	time:    2,
	threads: 4,
	saltLen: 16,
	keyLen:  32,
}

var b64 = base64.RawStdEncoding

// ErrInvalidHash is returned when a stored hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid argon2id hash")

// HashPassword returns a PHC-formatted Argon2id hash of plain.
func HashPassword(plain string) (string, error) {
	p := defaultParams
	salt := make([]byte, p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, p.time, p.memory, p.threads, p.keyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether plain matches the PHC-formatted encoded hash.
// It returns an error only if the encoded hash is malformed.
func VerifyPassword(plain, encoded string) (bool, error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(plain), salt, p.time, p.memory, p.threads, p.keyLen)
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}

func decodeHash(encoded string) (argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return argon2Params{}, nil, nil, fmt.Errorf("%w: version %d", ErrInvalidHash, version)
	}

	var mem, iters, threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &threads); err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}
	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return argon2Params{}, nil, nil, ErrInvalidHash
	}

	p := argon2Params{
		memory:  mem,
		time:    iters,
		threads: uint8(threads),
		saltLen: uint32(len(salt)),
		keyLen:  uint32(len(hash)),
	}
	return p, salt, hash, nil
}
