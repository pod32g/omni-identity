//go:build !linux && !darwin

package enrollment

import (
	"errors"
	"net"
)

// peerUID is Linux- and macOS-only; elsewhere the broker refuses every
// caller unless a test supplies its own PeerUID.
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials unsupported on this OS")
}
