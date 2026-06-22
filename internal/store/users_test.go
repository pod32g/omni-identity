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

func TestUpsertExternalUserInsertThenUpdate(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	u, err := db.UpsertExternalUser(ctx, "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if u.AuthSource != "ldap" || u.PasswordHash != "" || u.ID == "" || u.ExternalID != "uid=jane,dc=x" {
		t.Fatalf("bad insert: %+v", u)
	}
	if u.IsLocal() {
		t.Fatal("ldap user must not report IsLocal")
	}

	u2, err := db.UpsertExternalUser(ctx, "ldap", "uid=jane,dc=x", "jane", "j2@x", "Jane D", true)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u2.ID != u.ID || !u2.IsAdmin || u2.Email != "j2@x" {
		t.Fatalf("bad update: %+v", u2)
	}

	got, err := db.GetUserByExternalID(ctx, "ldap", "uid=jane,dc=x")
	if err != nil || got.ID != u.ID {
		t.Fatalf("GetUserByExternalID: %v / %+v", err, got)
	}
}

func TestUpsertExternalUserRefusesLocalCollision(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if err := db.CreateUser(ctx, newUser("bob")); err != nil {
		t.Fatalf("seed local: %v", err)
	}
	if _, err := db.UpsertExternalUser(ctx, "ldap", "uid=bob,dc=x", "bob", "b@y", "Bob", false); err == nil {
		t.Fatal("must refuse to shadow a local account with the same username")
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

func TestDeleteUser(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("gone")
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := db.GetUserByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("user still present after delete: %v", err)
	}
	// Deleting a non-existent row reports ErrNotFound.
	if err := db.DeleteUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestLinkUserToExternal(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := newUser("alice") // local, with a password hash
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := db.LinkUserToExternal(ctx, u.ID, "ldap", "uid=alice,dc=x"); err != nil {
		t.Fatalf("LinkUserToExternal: %v", err)
	}
	got, _ := db.GetUserByID(ctx, u.ID)
	if got.IsLocal() || got.AuthSource != "ldap" || got.ExternalID != "uid=alice,dc=x" {
		t.Fatalf("not promoted: %+v", got)
	}
	if got.PasswordHash != "" {
		t.Errorf("local hash must be cleared, got %q", got.PasswordHash)
	}

	// A second row cannot link to the same directory entry (unique index).
	other := newUser("bob")
	if err := db.CreateUser(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := db.LinkUserToExternal(ctx, other.ID, "ldap", "uid=alice,dc=x"); err == nil {
		t.Error("expected a unique-violation linking two rows to the same DN")
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
