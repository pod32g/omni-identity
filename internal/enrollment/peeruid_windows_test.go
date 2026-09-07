//go:build windows

package enrollment

import (
	"os"
	"testing"
)

// On Windows every process has uid -1 (Go's os.Getuid), the same value
// SignIn records; the broker must not mistake it for root.
func TestBrokerKeyedUIDOnWindows(t *testing.T) {
	if privilegedUID(os.Getuid()) {
		t.Fatalf("uid %d refused as privileged on Windows", os.Getuid())
	}
	if uid, err := peerUID(nil); err != nil || uid != os.Getuid() {
		t.Fatalf("peerUID = %d, %v", uid, err)
	}
}
