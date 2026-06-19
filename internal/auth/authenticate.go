package auth

import (
	"context"
	"errors"

	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

// ErrInvalidCredentials is returned for any failed login (unknown user, wrong
// password, or disabled account) so callers cannot distinguish the cases.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// UserLookup is the persistence surface Authenticate needs.
type UserLookup interface {
	GetUserByUsername(ctx context.Context, username string) (*model.User, error)
}

// dummyHash is a valid Argon2id hash used to equalize timing when the user is
// not found, mitigating username enumeration via response time.
var dummyHash, _ = HashPassword("omni-identity-dummy-password")

// Authenticate verifies a username/password pair and returns the user if the
// credentials are valid and the account is enabled.
func Authenticate(ctx context.Context, lookup UserLookup, username, password string) (*model.User, error) {
	u, err := lookup.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		// Compare against a dummy hash to keep timing constant.
		_, _ = VerifyPassword(password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	ok, err := VerifyPassword(password, u.PasswordHash)
	if err != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	if u.Disabled {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}
