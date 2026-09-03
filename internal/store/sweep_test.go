package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

func TestSweepExpiredRemovesOnlyStaleRows(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	u := seedUser(t, db, "alice")
	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	mk := func(exp time.Time) {
		_ = db.CreateSession(ctx, &model.Session{ID: uuid.NewString(), UserID: u.ID, CSRFSecret: "c", CreatedAt: past, ExpiresAt: exp})
		_ = db.CreateLoginChallenge(ctx, &model.LoginChallenge{ID: uuid.NewString(), UserID: u.ID, CreatedAt: past, ExpiresAt: exp})
		_ = db.CreateDeviceCode(ctx, &model.DeviceCode{ID: uuid.NewString(), DeviceCodeHash: uuid.NewString(), UserCode: uuid.NewString()[:8], ClientID: "c", Scope: "openid", Status: model.DeviceCodePending, CreatedAt: past, ExpiresAt: exp})
		_ = db.CreateWebAuthnCeremony(ctx, &model.WebAuthnCeremony{ID: uuid.NewString(), Purpose: "login", SessionData: "{}", CreatedAt: past, ExpiresAt: exp})
		_, _ = db.ConsumeJTI(ctx, uuid.NewString(), "", exp)
	}
	mk(past)
	mk(future)

	counts, err := db.SweepExpired(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "login_challenges", "device_codes", "webauthn_ceremonies"} {
		if counts[table] != 1 {
			t.Errorf("%s: swept %d, want 1", table, counts[table])
		}
	}
	// ConsumeJTI prunes on insert, so the stale row was already gone.
	if n, _ := db.CountActiveSessions(ctx); n != 1 {
		t.Errorf("live session removed: %d left", n)
	}
	if codes := db.PendingUserCodesForTest(ctx); len(codes) != 1 {
		t.Errorf("live device code removed: %d left", len(codes))
	}
}
