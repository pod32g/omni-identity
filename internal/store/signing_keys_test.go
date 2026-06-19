package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

func newSigningKey(kid, alg string, active bool) *model.SigningKey {
	return &model.SigningKey{
		KID:        kid,
		Alg:        alg,
		PublicJWK:  `{"kty":"test","kid":"` + kid + `"}`,
		PrivatePEM: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
		Active:     active,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
}

func TestCreateAndListSigningKeys(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if err := db.CreateSigningKey(ctx, newSigningKey("k1", "RS256", true)); err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	if err := db.CreateSigningKey(ctx, newSigningKey("k2", "EdDSA", true)); err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	keys, err := db.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListSigningKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("len = %d, want 2", len(keys))
	}
}

func TestGetActiveSigningKey(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateSigningKey(ctx, newSigningKey("rsa-old", "RS256", false))
	_ = db.CreateSigningKey(ctx, newSigningKey("rsa-new", "RS256", true))

	k, err := db.GetActiveSigningKey(ctx, "RS256")
	if err != nil {
		t.Fatalf("GetActiveSigningKey: %v", err)
	}
	if k.KID != "rsa-new" {
		t.Errorf("kid = %q, want rsa-new (active)", k.KID)
	}
}

func TestGetActiveSigningKeyNotFound(t *testing.T) {
	db := tempDB(t)
	if _, err := db.GetActiveSigningKey(context.Background(), "RS256"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
