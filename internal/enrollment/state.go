package enrollment

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// State is the persisted enrollment record (device.json). It holds no secrets:
// the private key lives in its own file and tokens are never written here.
type State struct {
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	DeviceID      string    `json:"device_id"`
	Fingerprint   string    `json:"fingerprint"`
	Name          string    `json:"name"`
	OwnerSub      string    `json:"owner_sub"`
	OwnerUsername string    `json:"owner_username"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	// Status is the last status Omni reported (active | revoked). Updated by
	// status/renew/daemon; "revoked" is sticky until unenroll.
	Status        string    `json:"status"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`
	// AllowInsecureHTTP records the operator's explicit opt-in to an http://
	// issuer (private-network testing only).
	AllowInsecureHTTP bool   `json:"allow_insecure_http,omitempty"`
	CAFile            string `json:"ca_file,omitempty"`
	// KeyBackend records where the device key lives (file | tpm) and, for a
	// TPM, which device; rotation keeps using the same backend.
	KeyBackend string `json:"key_backend,omitempty"`
	TPMDevice  string `json:"tpm_device,omitempty"`
}

const stateFileName = "device.json"

// ErrNotEnrolled is returned by LoadState when the device has no record.
var ErrNotEnrolled = errors.New("device is not enrolled")

// LoadState reads device.json from dir.
func LoadState(dir string) (*State, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if st.DeviceID == "" {
		return nil, ErrNotEnrolled
	}
	return &st, nil
}

// SaveState writes device.json atomically (0600).
func SaveState(dir string, st *State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// RemoveState deletes device.json and the key (unenroll).
func RemoveState(dir string) error {
	for _, f := range []string{stateFileName, keyFileName, tpmBlobFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Status is the daemon's runtime view, written to status.json for local
// tooling (and, later, the Linux login integration). No tokens inside.
type Status struct {
	DeviceID        string    `json:"device_id"`
	Status          string    `json:"status"` // active | revoked | unknown
	TrustLevel      string    `json:"trust_level,omitempty"`
	IssuerReachable bool      `json:"issuer_reachable"`
	LastRenewedAt   time.Time `json:"last_renewed_at,omitempty"`
	TokenExpiresAt  time.Time `json:"token_expires_at,omitempty"`
	LastCheckedAt   time.Time `json:"last_checked_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}

// WriteStatus writes status.json atomically (0644: it holds no secrets and
// local readers such as a status command run unprivileged).
func WriteStatus(dir string, st *Status) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path+".tmp", raw, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// ReadStatus reads status.json.
func ReadStatus(dir string) (*Status, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
