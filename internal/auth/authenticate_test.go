package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func seedUser(t *testing.T, db interface {
	CreateUser(context.Context, *model.User) error
}, username, password string, disabled bool) *model.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	u := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: hash,
		Disabled:     disabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestAuthenticateSuccess(t *testing.T) {
	db := testStore(t)
	seedUser(t, db, "alice", "s3cret", false)

	u, err := Authenticate(context.Background(), db, "alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q", u.Username)
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	db := testStore(t)
	seedUser(t, db, "bob", "right", false)

	if _, err := Authenticate(context.Background(), db, "bob", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticateUnknownUser(t *testing.T) {
	db := testStore(t)
	if _, err := Authenticate(context.Background(), db, "ghost", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticateDisabledUser(t *testing.T) {
	db := testStore(t)
	seedUser(t, db, "carol", "pw", true)

	if _, err := Authenticate(context.Background(), db, "carol", "pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("disabled user must not authenticate, err = %v", err)
	}
}
