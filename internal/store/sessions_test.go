package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func newSession(t *testing.T, db *DB, ttl time.Duration) *model.Session {
	t.Helper()
	ctx := context.Background()
	u := newUser("sess-" + uuid.NewString()[:8])
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user for session: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return &model.Session{
		ID:         uuid.NewString(),
		UserID:     u.ID,
		CSRFSecret: "csrf-secret",
		UserAgent:  "test-agent",
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
}

func TestCreateAndGetSession(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	s := newSession(t, db, time.Hour)

	if err := db.CreateSession(ctx, s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := db.GetSession(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != s.UserID || got.CSRFSecret != s.CSRFSecret {
		t.Errorf("got %+v, want %+v", got, s)
	}
}

func TestGetExpiredSessionReturnsNotFound(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	s := newSession(t, db, -time.Minute) // already expired
	if err := db.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSession(ctx, s.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for expired session", err)
	}
}

func TestDeleteSession(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	s := newSession(t, db, time.Hour)
	_ = db.CreateSession(ctx, s)

	if err := db.DeleteSession(ctx, s.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := db.GetSession(ctx, s.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("session should be gone, err = %v", err)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	expired := newSession(t, db, -time.Hour)
	valid := newSession(t, db, time.Hour)
	_ = db.CreateSession(ctx, expired)
	_ = db.CreateSession(ctx, valid)

	n, err := db.DeleteExpiredSessions(ctx, time.Now())
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}
	// valid session must still resolve
	if _, err := db.GetSession(ctx, valid.ID); err != nil {
		t.Errorf("valid session removed: %v", err)
	}
}
