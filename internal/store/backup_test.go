package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestBackupToCreatesValidSnapshot(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	if err := db.CreateUser(ctx, newUser("alice")); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "snapshot.db")
	if err := db.BackupTo(ctx, out); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	// The snapshot must be a valid, openable database containing the data.
	snap, err := Open(out)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()
	if _, err := snap.GetUserByUsername(ctx, "alice"); err != nil {
		t.Errorf("snapshot missing data: %v", err)
	}
}

func TestBackupToRejectsExistingDestination(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "exists.db")
	// First backup creates it; VACUUM INTO must refuse to overwrite.
	if err := db.BackupTo(ctx, out); err != nil {
		t.Fatal(err)
	}
	if err := db.BackupTo(ctx, out); err == nil {
		t.Error("BackupTo should refuse to overwrite an existing file")
	}
}

func TestIntegrityCheckOK(t *testing.T) {
	db := tempDB(t)
	ok, problems, err := db.IntegrityCheck(context.Background())
	if err != nil {
		t.Fatalf("IntegrityCheck: %v", err)
	}
	if !ok {
		t.Errorf("expected ok integrity, got problems: %v", problems)
	}
}
