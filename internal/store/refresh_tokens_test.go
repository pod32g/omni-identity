package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func newRefreshToken(hash, userID, clientID string) *model.RefreshToken {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.RefreshToken{
		ID:        uuid.NewString(),
		TokenHash: hash,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     "openid offline_access",
		ExpiresAt: now.Add(720 * time.Hour),
		CreatedAt: now,
	}
}

func TestCreateAndGetRefreshToken(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	rt := newRefreshToken("rh-1", "user-1", "jellyfin")
	if err := db.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	got, err := db.GetRefreshTokenByHash(ctx, "rh-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if got.ID != rt.ID || got.Revoked {
		t.Errorf("unexpected token: %+v", got)
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	rt := newRefreshToken("rh-2", "user-1", "jellyfin")
	_ = db.CreateRefreshToken(ctx, rt)

	if err := db.RevokeRefreshToken(ctx, rt.ID); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	got, _ := db.GetRefreshTokenByHash(ctx, "rh-2")
	if !got.Revoked {
		t.Error("token should be revoked")
	}
}

func TestGetRefreshTokenNotFound(t *testing.T) {
	db := tempDB(t)
	if _, err := db.GetRefreshTokenByHash(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRevokeRefreshTokensForUserClient(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateRefreshToken(ctx, newRefreshToken("a", "user-1", "jellyfin"))
	_ = db.CreateRefreshToken(ctx, newRefreshToken("b", "user-1", "jellyfin"))
	_ = db.CreateRefreshToken(ctx, newRefreshToken("c", "user-1", "other"))

	if err := db.RevokeRefreshTokensForUserClient(ctx, "user-1", "jellyfin"); err != nil {
		t.Fatalf("RevokeRefreshTokensForUserClient: %v", err)
	}
	for _, h := range []string{"a", "b"} {
		got, _ := db.GetRefreshTokenByHash(ctx, h)
		if !got.Revoked {
			t.Errorf("token %q should be revoked", h)
		}
	}
	// Different client untouched.
	other, _ := db.GetRefreshTokenByHash(ctx, "c")
	if other.Revoked {
		t.Error("token for a different client must not be revoked")
	}
}
