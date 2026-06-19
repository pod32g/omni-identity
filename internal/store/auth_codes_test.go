package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

func newAuthCode(hash string, ttl time.Duration) *model.AuthorizationCode {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.AuthorizationCode{
		CodeHash:            hash,
		ClientID:            "jellyfin",
		UserID:              "user-1",
		RedirectURI:         "https://app/cb",
		Scope:               "openid email",
		Nonce:               "n",
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(ttl),
		CreatedAt:           now,
	}
}

func TestCreateAndConsumeAuthCode(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if err := db.CreateAuthCode(ctx, newAuthCode("hash-1", 5*time.Minute)); err != nil {
		t.Fatalf("CreateAuthCode: %v", err)
	}

	got, err := db.ConsumeAuthCode(ctx, "hash-1")
	if err != nil {
		t.Fatalf("ConsumeAuthCode: %v", err)
	}
	if got.UserID != "user-1" || got.Scope != "openid email" {
		t.Errorf("unexpected code: %+v", got)
	}

	// Second consume must fail (single-use).
	if _, err := db.ConsumeAuthCode(ctx, "hash-1"); err == nil {
		t.Error("auth code must be single-use")
	}
}

func TestConsumeExpiredAuthCode(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateAuthCode(ctx, newAuthCode("hash-exp", -time.Minute))
	if _, err := db.ConsumeAuthCode(ctx, "hash-exp"); err == nil {
		t.Error("expired auth code must not be consumable")
	}
}

func TestConsumeMissingAuthCode(t *testing.T) {
	db := tempDB(t)
	if _, err := db.ConsumeAuthCode(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
