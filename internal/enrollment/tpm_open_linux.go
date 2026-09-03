//go:build linux

package enrollment

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func openDeviceTPM(path string) (transport.TPMCloser, error) { return linuxtpm.Open(path) }
