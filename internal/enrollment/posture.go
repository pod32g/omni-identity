package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
)

// Posture is what this device reports about itself at every renewal
// (POST /api/v1/devices/me/posture). Self-asserted: Omni Identity records
// it and shows it, relying parties may gate on it, nobody attests it.
type Posture struct {
	OSName        string `json:"os_name,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	DiskEncrypted *bool  `json:"disk_encrypted,omitempty"`
	ScreenLock    *bool  `json:"screen_lock,omitempty"`
	KeyBackend    string `json:"key_backend,omitempty"`
}

// ReportPosture sends the device's posture under its device token.
func (c *Client) ReportPosture(ctx context.Context, deviceToken string, p Posture) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Issuer+"/api/v1/devices/me/posture", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.authorize(req, deviceToken); err != nil {
		return err
	}
	return c.doJSON(req, nil)
}

// LocalPosture collects what this platform can determine without
// privileges; unknown facts stay nil. keyBackend is what the enrollment
// records (file, dpapi, tpm).
func LocalPosture(keyBackend string) Posture {
	p := collectPosture()
	p.OSName = orDefault(p.OSName, runtime.GOOS)
	p.KeyBackend = reportedKeyBackend(keyBackend)
	return p
}

// reportedKeyBackend names the backend the way Omni Identity classifies
// it: a "file" key on Windows is DPAPI-wrapped.
func reportedKeyBackend(backend string) string {
	if backend == "" {
		backend = KeyBackendFile
	}
	if backend == KeyBackendFile && runtime.GOOS == "windows" {
		return "dpapi"
	}
	return backend
}

func boolPtr(b bool) *bool { return &b }
