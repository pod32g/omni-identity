//go:build windows

package enrollment

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openDeviceTPM on Windows goes through the TPM Base Services; the path is
// ignored (there is one TPM). Whether a standard user may create keys is
// the platform's decision: on failure the "auto" backend falls back to a
// DPAPI-wrapped file key.
func openDeviceTPM(string) (transport.TPMCloser, error) { return windowstpm.Open() }
