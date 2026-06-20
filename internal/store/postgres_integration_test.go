package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

// openPostgresTest connects to the Postgres named by OMNI_TEST_POSTGRES_URL,
// resets its schema, runs migrations, and returns a clean store. The whole test
// skips when the env var is unset, so the default `go test` run never needs a
// database. Run it with, e.g.:
//
//	docker run -d --name omni-pg -e POSTGRES_PASSWORD=omni -e POSTGRES_USER=omni \
//	  -e POSTGRES_DB=omni -p 5432:5432 postgres:16-alpine
//	OMNI_TEST_POSTGRES_URL='postgres://omni:omni@localhost:5432/omni?sslmode=disable' \
//	  go test ./internal/store/ -run Postgres -v
func openPostgresTest(t *testing.T) *DB {
	t.Helper()
	url := os.Getenv("OMNI_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("set OMNI_TEST_POSTGRES_URL to run the Postgres integration test")
	}
	// Reset to a clean schema so migrations apply from scratch each run.
	raw, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	for _, stmt := range []string{`DROP SCHEMA public CASCADE`, `CREATE SCHEMA public`} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	_ = raw.Close()

	db, err := OpenWith(DriverPostgres, url)
	if err != nil {
		t.Fatalf("OpenWith postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if db.dialect != dialectPostgres {
		t.Fatalf("dialect = %v, want postgres", db.dialect)
	}
	return db
}

// TestPostgresBackendIntegration exercises every dialect-sensitive path against
// a real Postgres: BOOLEAN/BYTEA/TIMESTAMPTZ columns, the ON CONFLICT upsert,
// transactions, and the atomic lockout UPDATE.
func TestPostgresBackendIntegration(t *testing.T) {
	db := openPostgresTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Users: booleans + timestamps round-trip.
	u := &model.User{
		ID: uuid.NewString(), Username: "alice", Email: "alice@example.com",
		PasswordHash: "hash", IsAdmin: true, MFAEnabled: true, TOTPSecret: "enc",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := db.GetUserByUsername(ctx, "alice")
	if err != nil || !got.IsAdmin || !got.MFAEnabled {
		t.Fatalf("GetUserByUsername round-trip failed: %+v err=%v", got, err)
	}

	// Atomic lockout UPDATE (CASE) + read-back.
	count, err := db.RecordFailedLogin(ctx, u.ID, 3, now.Add(time.Hour))
	if err != nil || count != 1 {
		t.Fatalf("RecordFailedLogin #1: count=%d err=%v", count, err)
	}
	_, _ = db.RecordFailedLogin(ctx, u.ID, 3, now.Add(time.Hour))
	count, _ = db.RecordFailedLogin(ctx, u.ID, 3, now.Add(time.Hour))
	if count != 3 {
		t.Fatalf("lockout count = %d, want 3", count)
	}
	locked, _ := db.GetUserByID(ctx, u.ID)
	if !locked.IsLocked(time.Now()) {
		t.Error("account should be locked after threshold")
	}
	if err := db.ResetFailedLogins(ctx, u.ID); err != nil {
		t.Fatalf("ResetFailedLogins: %v", err)
	}

	// Clients: JSON-text arrays + BOOLEAN skip_consent.
	c := &model.Client{
		ClientID: "app", Name: "App", Type: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://app/cb"}, AllowedScopes: []string{"openid"},
		PostLogoutRedirectURIs: []string{"https://app/bye"}, SkipConsent: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	gc, err := db.GetClient(ctx, "app")
	if err != nil || !gc.SkipConsent || len(gc.PostLogoutRedirectURIs) != 1 {
		t.Fatalf("GetClient round-trip: %+v err=%v", gc, err)
	}

	// Branding: BYTEA logo round-trip + default row.
	b, err := db.GetBranding(ctx)
	if err != nil || b.ProductName != "Omni Identity" {
		t.Fatalf("GetBranding default: %+v err=%v", b, err)
	}
	if err := db.SetBrandingLogo(ctx, []byte("PNGDATA"), "image/png"); err != nil {
		t.Fatalf("SetBrandingLogo: %v", err)
	}
	if b, _ = db.GetBranding(ctx); string(b.LogoBytes) != "PNGDATA" {
		t.Errorf("logo bytes = %q", b.LogoBytes)
	}

	// App secret: ON CONFLICT upsert is stable across calls.
	gen := func() (string, error) { return "key-" + uuid.NewString(), nil }
	k1, err := db.GetOrCreateAppSecret(ctx, gen)
	if err != nil {
		t.Fatalf("GetOrCreateAppSecret: %v", err)
	}
	k2, _ := db.GetOrCreateAppSecret(ctx, gen)
	if k1 != k2 {
		t.Errorf("app secret changed across calls: %q != %q", k1, k2)
	}

	// Refresh token + transactional rotation.
	rt := &model.RefreshToken{
		ID: uuid.NewString(), TokenHash: "h1", ClientID: "app", UserID: u.ID,
		Scope: "openid", ExpiresAt: now.Add(time.Hour), CreatedAt: now, AuthTime: now,
	}
	if err := db.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	newRT := &model.RefreshToken{
		ID: uuid.NewString(), TokenHash: "h2", ClientID: "app", UserID: u.ID,
		Scope: "openid", RotatedFrom: rt.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now, AuthTime: now,
	}
	ok, err := db.RotateRefreshToken(ctx, rt.ID, newRT)
	if err != nil || !ok {
		t.Fatalf("RotateRefreshToken: ok=%v err=%v", ok, err)
	}
	if ok, _ := db.RotateRefreshToken(ctx, rt.ID, nil); ok {
		t.Error("re-rotating a revoked token must report ok=false")
	}

	// Auth requests: expiry filtering.
	live := &model.AuthRequest{
		ID: "live", ClientID: "app", RedirectURI: "https://app/cb", ResponseType: "code",
		Scope: "openid", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	expired := &model.AuthRequest{
		ID: "old", ClientID: "app", RedirectURI: "https://app/cb", ResponseType: "code",
		Scope: "openid", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute),
	}
	_ = db.CreateAuthRequest(ctx, live)
	_ = db.CreateAuthRequest(ctx, expired)
	if _, err := db.GetAuthRequest(ctx, "live"); err != nil {
		t.Errorf("live auth request: %v", err)
	}
	if _, err := db.GetAuthRequest(ctx, "old"); err == nil {
		t.Error("expired auth request should read as not found")
	}

	// Audit log: BOOLEAN success.
	if err := db.AppendAuditEvent(ctx, &model.AuditEvent{
		ID: uuid.NewString(), CreatedAt: now, Event: "login.success",
		Username: "alice", Success: true,
	}); err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}
	events, err := db.ListAuditEvents(ctx, 10)
	if err != nil || len(events) != 1 || !events[0].Success {
		t.Fatalf("ListAuditEvents: %+v err=%v", events, err)
	}

	// Recovery codes: transactional replace + single-use consume.
	codes := []model.RecoveryCode{
		{ID: uuid.NewString(), CodeHash: "rc1", CreatedAt: now},
		{ID: uuid.NewString(), CodeHash: "rc2", CreatedAt: now},
	}
	if err := db.ReplaceRecoveryCodes(ctx, u.ID, codes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	used, err := db.ConsumeRecoveryCode(ctx, u.ID, "rc1")
	if err != nil || !used {
		t.Fatalf("ConsumeRecoveryCode: used=%v err=%v", used, err)
	}
	if used, _ := db.ConsumeRecoveryCode(ctx, u.ID, "rc1"); used {
		t.Error("recovery code must be single-use")
	}
	if n, _ := db.CountRecoveryCodes(ctx, u.ID); n != 1 {
		t.Errorf("remaining recovery codes = %d, want 1", n)
	}

	// Sessions: list + revoke-others, TIMESTAMPTZ + amr.
	s1 := &model.Session{ID: "s1", UserID: u.ID, CSRFSecret: "x", AMR: "pwd",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	s2 := &model.Session{ID: "s2", UserID: u.ID, CSRFSecret: "y", AMR: "pwd mfa",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	_ = db.CreateSession(ctx, s1)
	_ = db.CreateSession(ctx, s2)
	if sl, _ := db.ListSessionsForUser(ctx, u.ID); len(sl) != 2 {
		t.Errorf("sessions = %d, want 2", len(sl))
	}
	if n, _ := db.DeleteSessionsForUser(ctx, u.ID, "s1"); n != 1 {
		t.Errorf("revoked %d sessions, want 1", n)
	}

	// SQLite-only maintenance helpers must refuse on Postgres.
	if err := db.BackupTo(ctx, "/tmp/x"); err == nil {
		t.Error("BackupTo should be rejected on postgres")
	}
}
