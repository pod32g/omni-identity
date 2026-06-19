package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func newUser(username string) *model.User {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: "argon2id$hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestCreateAndGetUserByUsername(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("alice")

	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := db.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != u.ID || got.Email != u.Email || got.PasswordHash != u.PasswordHash {
		t.Errorf("got %+v, want %+v", got, u)
	}
}

func TestGetUserByIDRoundTrip(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("carol")
	u.IsAdmin = true
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := db.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !got.IsAdmin {
		t.Error("is_admin not persisted")
	}
}

func TestGetUserNotFound(t *testing.T) {
	db := tempDB(t)
	if _, err := db.GetUserByUsername(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCreateUserRejectsDuplicateUsername(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if err := db.CreateUser(ctx, newUser("bob")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	dup := newUser("bob") // same username, different id
	if err := db.CreateUser(ctx, dup); err == nil {
		t.Error("expected error creating duplicate username")
	}
}

func TestSetUserPassword(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("dave")
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserPassword(ctx, u.ID, "new-hash"); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	got, _ := db.GetUserByID(ctx, u.ID)
	if got.PasswordHash != "new-hash" {
		t.Errorf("password hash = %q, want new-hash", got.PasswordHash)
	}
}

func TestSetUserDisabled(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("erin")
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	got, _ := db.GetUserByID(ctx, u.ID)
	if !got.Disabled {
		t.Error("user should be disabled")
	}
}

func TestUpdateUser(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("frank")
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u.Email = "frank.new@example.com"
	u.IsAdmin = true
	if err := db.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ := db.GetUserByID(ctx, u.ID)
	if got.Email != "frank.new@example.com" || !got.IsAdmin {
		t.Errorf("update not persisted: %+v", got)
	}
}

func TestCountAdmins(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if n, _ := db.CountAdmins(ctx); n != 0 {
		t.Fatalf("initial admin count = %d, want 0", n)
	}
	admin := newUser("root")
	admin.IsAdmin = true
	_ = db.CreateUser(ctx, admin)
	_ = db.CreateUser(ctx, newUser("plain"))
	if n, _ := db.CountAdmins(ctx); n != 1 {
		t.Errorf("admin count = %d, want 1", n)
	}
}

func TestListUsers(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateUser(ctx, newUser("u1"))
	_ = db.CreateUser(ctx, newUser("u2"))
	users, err := db.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Errorf("len = %d, want 2", len(users))
	}
}
