package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

func newClient(id string) *model.Client {
	now := time.Now().UTC().Truncate(time.Second)
	return &model.Client{
		ClientID:         id,
		ClientSecretHash: "secret-hash",
		Name:             "App " + id,
		RedirectURIs:     []string{"https://app.example.com/callback"},
		AllowedScopes:    []string{"openid", "email", "profile"},
		Type:             model.ClientTypeConfidential,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func TestCreateAndGetClient(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	c := newClient("jellyfin")
	if err := db.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := db.GetClient(ctx, "jellyfin")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !reflect.DeepEqual(got.RedirectURIs, c.RedirectURIs) {
		t.Errorf("redirect uris = %v, want %v", got.RedirectURIs, c.RedirectURIs)
	}
	if !reflect.DeepEqual(got.AllowedScopes, c.AllowedScopes) {
		t.Errorf("scopes = %v, want %v", got.AllowedScopes, c.AllowedScopes)
	}
	if got.Type != model.ClientTypeConfidential {
		t.Errorf("type = %q", got.Type)
	}
}

func TestGetClientNotFound(t *testing.T) {
	db := tempDB(t)
	if _, err := db.GetClient(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestListClients(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateClient(ctx, newClient("a"))
	_ = db.CreateClient(ctx, newClient("b"))
	list, err := db.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}
}

func TestUpdateClient(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	c := newClient("app")
	_ = db.CreateClient(ctx, c)

	c.Name = "Renamed"
	c.RedirectURIs = []string{"https://new.example.com/cb", "https://alt.example.com/cb"}
	c.AllowedScopes = []string{"openid"}
	if err := db.UpdateClient(ctx, c); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got, _ := db.GetClient(ctx, "app")
	if got.Name != "Renamed" || len(got.RedirectURIs) != 2 || len(got.AllowedScopes) != 1 {
		t.Errorf("update not persisted: %+v", got)
	}
}

func TestSetClientDisabled(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateClient(ctx, newClient("app"))
	if err := db.SetClientDisabled(ctx, "app", true); err != nil {
		t.Fatalf("SetClientDisabled: %v", err)
	}
	got, _ := db.GetClient(ctx, "app")
	if !got.Disabled {
		t.Error("client should be disabled")
	}
}

func TestSetClientSecretHash(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	_ = db.CreateClient(ctx, newClient("app"))
	if err := db.SetClientSecretHash(ctx, "app", "new-hash"); err != nil {
		t.Fatalf("SetClientSecretHash: %v", err)
	}
	got, _ := db.GetClient(ctx, "app")
	if got.ClientSecretHash != "new-hash" {
		t.Errorf("secret hash = %q, want new-hash", got.ClientSecretHash)
	}
}
