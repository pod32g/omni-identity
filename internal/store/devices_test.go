package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func seedUser(t *testing.T, db *DB, name string) *model.User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u := &model.User{ID: uuid.NewString(), Username: name, Email: name + "@x", PasswordHash: "h", CreatedAt: now, UpdatedAt: now}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func seedDevice(t *testing.T, db *DB, owner string, fp string) *model.Device {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	d := &model.Device{
		ID: uuid.NewString(), OwnerUserID: owner, Name: "laptop", Hostname: "laptop.lan", Platform: "linux",
		Architecture: "arm64", PublicKey: `{"crv":"Ed25519","kty":"OKP","x":"AA"}`, PublicKeyAlgorithm: "EdDSA",
		Fingerprint: fp, Status: model.DeviceStatusActive, TrustLevel: model.DeviceTrustEnrolled,
		CreatedAt: now, EnrolledAt: now,
	}
	if err := db.CreateDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDeviceLifecycle(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := seedUser(t, db, "alice")
	d := seedDevice(t, db, u.ID, "fp-1")

	got, err := db.GetDevice(ctx, d.ID)
	if err != nil || !got.IsActive() || got.EnrolledAt.IsZero() || !got.LastSeenAt.IsZero() {
		t.Fatalf("GetDevice: %+v err=%v", got, err)
	}
	if inUse, _ := db.FingerprintInUse(ctx, "fp-1"); !inUse {
		t.Error("fingerprint should be in use")
	}
	// Fingerprints are globally unique, even across owners.
	if err := db.CreateDevice(ctx, &model.Device{ID: uuid.NewString(), OwnerUserID: u.ID, PublicKey: "k", PublicKeyAlgorithm: "EdDSA", Fingerprint: "fp-1", CreatedAt: time.Now()}); err == nil {
		t.Error("duplicate fingerprint accepted")
	}

	_ = db.TouchDevice(ctx, d.ID, time.Now())
	if got, _ := db.GetDevice(ctx, d.ID); got.LastSeenAt.IsZero() {
		t.Error("TouchDevice did not set last_seen_at")
	}
	if n, _ := db.CountActiveDevices(ctx); n != 1 {
		t.Errorf("active = %d", n)
	}

	// A device-bound refresh token is revoked with the device.
	rt := &model.RefreshToken{ID: uuid.NewString(), TokenHash: "rth", ClientID: "c", UserID: u.ID, Scope: "openid",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), AuthTime: time.Now(), DeviceID: d.ID, DPoPJKT: "fp-1", AMR: "pwd"}
	if err := db.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetRefreshTokenByHash(ctx, "rth"); got.DeviceID != d.ID || got.DPoPJKT != "fp-1" || got.AMR != "pwd" {
		t.Errorf("refresh token bindings not persisted: %+v", got)
	}
	if err := db.DeleteDevice(ctx, d.ID); err != ErrNotFound {
		t.Errorf("deleting an active device must fail, got %v", err)
	}
	if err := db.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeDevice(ctx, d.ID, time.Now()); err != ErrNotFound {
		t.Errorf("second revoke should report ErrNotFound, got %v", err)
	}
	if got, _ := db.GetDevice(ctx, d.ID); got.Status != model.DeviceStatusRevoked || got.RevokedAt.IsZero() {
		t.Errorf("not revoked: %+v", got)
	}
	if got, _ := db.GetRefreshTokenByHash(ctx, "rth"); !got.Revoked {
		t.Error("device-bound refresh token should be revoked with the device")
	}
	if err := db.RotateDeviceKey(ctx, d.ID, "k2", "EdDSA", "fp-2"); err != ErrNotFound {
		t.Errorf("rotation on a revoked device must fail, got %v", err)
	}
	// Revoked fingerprints stay reserved; the row can be deleted afterwards.
	if inUse, _ := db.FingerprintInUse(ctx, "fp-1"); !inUse {
		t.Error("revoked fingerprint should remain reserved")
	}
	if err := db.DeleteDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetDevice(ctx, d.ID); err != ErrNotFound {
		t.Error("device should be gone")
	}
}

func TestDeviceRotateKeyKeepsPreviousFingerprint(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := seedUser(t, db, "bob")
	d := seedDevice(t, db, u.ID, "old")
	if err := db.RotateDeviceKey(ctx, d.ID, "newkey", "ES256", "new"); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetDevice(ctx, d.ID)
	if got.Fingerprint != "new" || got.PreviousFingerprint != "old" || got.PublicKeyAlgorithm != "ES256" {
		t.Errorf("rotate: %+v", got)
	}
	if inUse, _ := db.FingerprintInUse(ctx, "old"); !inUse {
		t.Error("previous fingerprint must stay reserved")
	}
	devs, _ := db.ListDevicesForUser(ctx, u.ID)
	if len(devs) != 1 {
		t.Errorf("list = %d", len(devs))
	}
}

func TestDeviceDeletedWithOwner(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := seedUser(t, db, "carol")
	d := seedDevice(t, db, u.ID, "fp-c")
	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetDevice(ctx, d.ID); err != ErrNotFound {
		t.Error("device should cascade-delete with its owner")
	}
}

func TestConsumeJTIIsSingleUse(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if ok, err := db.ConsumeJTI(ctx, "h1", "d", exp); err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	if ok, _ := db.ConsumeJTI(ctx, "h1", "d", exp); ok {
		t.Error("replayed jti accepted")
	}
	// An expired identifier is pruned and may be reused.
	if ok, _ := db.ConsumeJTI(ctx, "h2", "d", time.Now().Add(-time.Minute)); !ok {
		t.Fatal("insert expired")
	}
	if ok, _ := db.ConsumeJTI(ctx, "h2", "d", exp); !ok {
		t.Error("expired jti should have been pruned")
	}
}

func TestDeviceCodeStateMachine(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	dc := &model.DeviceCode{ID: uuid.NewString(), DeviceCodeHash: "dch", UserCode: "BCDFGHJK", ClientID: "omni-enrollment",
		Scope: "openid device:enroll", Status: model.DeviceCodePending, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if err := db.CreateDeviceCode(ctx, dc); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetPendingDeviceCodeByUserCode(ctx, "BCDFGHJK"); err != nil || got.ID != dc.ID {
		t.Fatalf("pending lookup: %+v err=%v", got, err)
	}
	if ok, _ := db.ConsumeDeviceCode(ctx, dc.ID); ok {
		t.Error("pending code must not be consumable")
	}
	if err := db.ApproveDeviceCode(ctx, dc.ID, "u1", "pwd otp", now); err != nil {
		t.Fatal(err)
	}
	if err := db.ApproveDeviceCode(ctx, dc.ID, "u2", "pwd", now); err != ErrNotFound {
		t.Error("double approval must fail")
	}
	if _, err := db.GetPendingDeviceCodeByUserCode(ctx, "BCDFGHJK"); err != ErrNotFound {
		t.Error("approved code must no longer be pending by user code")
	}
	got, _ := db.GetDeviceCodeByHash(ctx, "dch")
	if got.Status != model.DeviceCodeApproved || got.UserID != "u1" || got.AMR != "pwd otp" || got.AuthTime.IsZero() {
		t.Errorf("approved: %+v", got)
	}
	if ok, _ := db.ConsumeDeviceCode(ctx, dc.ID); !ok {
		t.Fatal("consume approved failed")
	}
	if ok, _ := db.ConsumeDeviceCode(ctx, dc.ID); ok {
		t.Error("device code consumed twice")
	}

	// Expired pending codes are invisible by user code and pruned by cleanup.
	old := &model.DeviceCode{ID: uuid.NewString(), DeviceCodeHash: "old", UserCode: "ZZZZZZZZ", ClientID: "c", Scope: "openid",
		Status: model.DeviceCodePending, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	_ = db.CreateDeviceCode(ctx, old)
	if _, err := db.GetPendingDeviceCodeByUserCode(ctx, "ZZZZZZZZ"); err != ErrNotFound {
		t.Error("expired code should not be pending")
	}
	if n, _ := db.DeleteExpiredDeviceCodes(ctx, time.Now()); n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
}

func TestBuiltInEnrollmentClientSeeded(t *testing.T) {
	db := tempDB(t)
	c, err := db.GetClient(context.Background(), model.EnrollmentClientID)
	if err != nil {
		t.Fatalf("built-in client missing: %v", err)
	}
	if !c.IsPublic() || !c.BuiltIn() || c.SkipConsent {
		t.Errorf("built-in client shape: %+v", c)
	}
	found := false
	for _, s := range c.AllowedScopes {
		if s == "device:enroll" {
			found = true
		}
	}
	if !found {
		t.Error("built-in client lacks device:enroll scope")
	}
}
