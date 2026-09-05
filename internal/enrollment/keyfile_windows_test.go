//go:build windows

package enrollment

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The key file written on Windows is DPAPI-wrapped, unreadable as PEM, and
// loads back to the same key for this user.
func TestKeyFileIsDPAPIWrappedOnWindows(t *testing.T) {
	dir := t.TempDir()
	k, err := GenerateKey(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, dpapiMagic) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatalf("key file is not DPAPI-wrapped: %q", raw[:20])
	}
	back, err := LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.Fingerprint() != k.Fingerprint() {
		t.Fatalf("fingerprint changed: %s vs %s", back.Fingerprint(), k.Fingerprint())
	}
	// A plain PEM copied from a Unix machine still loads.
	if _, err := GenerateKey(dir, true); err != nil {
		t.Fatal(err)
	}
}
