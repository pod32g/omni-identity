//go:build !linux

package enrollment

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
)

func openDeviceTPM(path string) (transport.TPMCloser, error) {
	return nil, fmt.Errorf("tpm: device %q is only supported on Linux (use tcp://host:port for a software TPM)", path)
}
