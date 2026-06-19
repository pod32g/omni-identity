package tokens

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/pod32g/omni-identity/internal/store"
)

func testStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestNewKeyManagerGeneratesBothKeys(t *testing.T) {
	db := testStore(t)
	ctx := context.Background()
	if _, err := NewKeyManager(ctx, db); err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	keys, _ := db.ListSigningKeys(ctx)
	if len(keys) != 2 {
		t.Fatalf("generated %d keys, want 2 (RS256 + EdDSA)", len(keys))
	}
	algs := map[string]bool{}
	for _, k := range keys {
		algs[k.Alg] = true
	}
	if !algs[AlgRS256] || !algs[AlgEdDSA] {
		t.Errorf("missing an algorithm: %v", algs)
	}
}

func TestNewKeyManagerIsIdempotent(t *testing.T) {
	db := testStore(t)
	ctx := context.Background()
	if _, err := NewKeyManager(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyManager(ctx, db); err != nil {
		t.Fatal(err)
	}
	keys, _ := db.ListSigningKeys(ctx)
	if len(keys) != 2 {
		t.Errorf("keys = %d, want 2 (must not regenerate existing)", len(keys))
	}
}

func TestJWKSPublishesBothKeysWithoutPrivateMaterial(t *testing.T) {
	db := testStore(t)
	km, err := NewKeyManager(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(km.JWKS(), &doc); err != nil {
		t.Fatalf("JWKS not valid JSON: %v", err)
	}
	if len(doc.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		if _, leaked := k["d"]; leaked {
			t.Error("JWKS leaked private key parameter 'd'")
		}
		if k["kid"] == nil || k["kid"] == "" {
			t.Error("JWKS key missing kid")
		}
		if k["use"] != "sig" {
			t.Errorf("use = %v, want sig", k["use"])
		}
	}
}

func TestSignerReturnsUsableRSAKey(t *testing.T) {
	db := testStore(t)
	km, err := NewKeyManager(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	s, err := km.Signer(AlgRS256)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if s.KID == "" || s.Alg != AlgRS256 {
		t.Errorf("bad signer: %+v", s)
	}
	if _, ok := s.Key.(*rsa.PrivateKey); !ok {
		t.Errorf("RS256 key is %T, want *rsa.PrivateKey", s.Key)
	}
	var _ crypto.Signer = s.Key
}

func TestSignerReturnsUsableEdDSAKey(t *testing.T) {
	db := testStore(t)
	km, err := NewKeyManager(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	s, err := km.Signer(AlgEdDSA)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, ok := s.Key.(ed25519.PrivateKey); !ok {
		t.Errorf("EdDSA key is %T, want ed25519.PrivateKey", s.Key)
	}
}

func TestDefaultSignerIsRS256(t *testing.T) {
	db := testStore(t)
	km, err := NewKeyManager(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if km.DefaultSigner().Alg != AlgRS256 {
		t.Errorf("default signer alg = %q, want RS256", km.DefaultSigner().Alg)
	}
}
