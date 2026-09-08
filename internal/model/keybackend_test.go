package model

import "testing"

func TestTrustForKeyBackend(t *testing.T) {
	hardware := []string{KeyBackendTPM, KeyBackendSecureEnclave, KeyBackendStrongBox, KeyBackendAndroidTEE}
	for _, b := range hardware {
		if got := TrustForKeyBackend(b); got != DeviceTrustHardware {
			t.Errorf("TrustForKeyBackend(%q) = %q, want %q", b, got, DeviceTrustHardware)
		}
	}
	enrolled := []string{KeyBackendFile, KeyBackendDPAPI, "software", "", "unknown"}
	for _, b := range enrolled {
		if got := TrustForKeyBackend(b); got != DeviceTrustEnrolled {
			t.Errorf("TrustForKeyBackend(%q) = %q, want %q", b, got, DeviceTrustEnrolled)
		}
	}
}
