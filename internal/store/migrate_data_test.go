package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

// openSQLiteTest opens a fresh SQLite store at a temp path with migrations applied.
func openSQLiteTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestCopyDataMigratesAllTables populates a SQLite source with rows that exercise
// the dialect-sensitive columns (INTEGER booleans, a BLOB logo, an FK'd session,
// and the seeded single-row settings/branding tables) and verifies CopyData
// reproduces them faithfully in a fresh Postgres destination.
func TestCopyDataMigratesAllTables(t *testing.T) {
	dst := openPostgresTest(t) // skips unless OMNI_TEST_POSTGRES_URL is set
	src := openSQLiteTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// --- populate the SQLite source ---
	u := &model.User{
		ID: uuid.NewString(), Username: "alice", Email: "alice@example.com",
		PasswordHash: "hash", IsAdmin: true, MFAEnabled: true, TOTPSecret: "enc",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := src.CreateUser(ctx, u); err != nil {
		t.Fatalf("seed CreateUser: %v", err)
	}
	c := &model.Client{
		ClientID: "app", Name: "App", Type: model.ClientTypeConfidential,
		RedirectURIs: []string{"https://app/cb"}, AllowedScopes: []string{"openid"},
		PostLogoutRedirectURIs: []string{"https://app/bye"}, SkipConsent: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := src.CreateClient(ctx, c); err != nil {
		t.Fatalf("seed CreateClient: %v", err)
	}
	sess := &model.Session{
		ID: "s1", UserID: u.ID, CSRFSecret: "x", AMR: "pwd",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
	}
	if err := src.CreateSession(ctx, sess); err != nil {
		t.Fatalf("seed CreateSession: %v", err)
	}
	if err := src.SetBrandingLogo(ctx, []byte("PNGDATA"), "image/png"); err != nil {
		t.Fatalf("seed SetBrandingLogo: %v", err)
	}
	if err := src.AppendAuditEvent(ctx, &model.AuditEvent{
		ID: uuid.NewString(), CreatedAt: now, Event: "login.success",
		Username: "alice", Success: true,
	}); err != nil {
		t.Fatalf("seed AppendAuditEvent: %v", err)
	}
	st, err := src.GetSettings(ctx)
	if err != nil {
		t.Fatalf("seed GetSettings: %v", err)
	}
	st.CookieSecure = false
	st.PasswordMinLength = 16
	if err := src.UpdateSettings(ctx, st); err != nil {
		t.Fatalf("seed UpdateSettings: %v", err)
	}

	// --- run the migration ---
	report, err := CopyData(ctx, src, dst)
	if err != nil {
		t.Fatalf("CopyData: %v", err)
	}

	// --- row-count parity per table ---
	counts := map[string]TableCount{}
	for _, tc := range report.Tables {
		counts[tc.Table] = tc
		if tc.SourceRows != tc.DestRows {
			t.Errorf("table %q: source=%d dest=%d (mismatch)", tc.Table, tc.SourceRows, tc.DestRows)
		}
	}
	if got := counts["users"].DestRows; got != 1 {
		t.Errorf("users dest rows = %d, want 1", got)
	}
	if got := counts["sessions"].DestRows; got != 1 {
		t.Errorf("sessions dest rows = %d, want 1", got)
	}

	// --- type fidelity in the destination (read back via the typed API) ---
	gotU, err := dst.GetUserByUsername(ctx, "alice")
	if err != nil || !gotU.IsAdmin || !gotU.MFAEnabled {
		t.Fatalf("dst user round-trip: %+v err=%v", gotU, err)
	}
	gotC, err := dst.GetClient(ctx, "app")
	if err != nil || !gotC.SkipConsent {
		t.Fatalf("dst client round-trip: %+v err=%v", gotC, err)
	}
	if sl, _ := dst.ListSessionsForUser(ctx, u.ID); len(sl) != 1 {
		t.Errorf("dst sessions = %d, want 1", len(sl))
	}
	if b, _ := dst.GetBranding(ctx); string(b.LogoBytes) != "PNGDATA" {
		t.Errorf("dst branding logo = %q, want PNGDATA", b.LogoBytes)
	}
	if ev, _ := dst.ListAuditEvents(ctx, 10); len(ev) != 1 || !ev[0].Success {
		t.Errorf("dst audit events = %+v, want 1 success", ev)
	}
	if s2, _ := dst.GetSettings(ctx); s2.CookieSecure || s2.PasswordMinLength != 16 {
		t.Errorf("dst settings overwrite failed: %+v", s2)
	}
}
