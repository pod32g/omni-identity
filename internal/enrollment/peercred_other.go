//go:build !linux

package enrollment

import "net"

// requireRootPeer is a no-op off Linux: the socket file mode (0600 root) is
// the only guard, and the PoC only ships on Linux.
func requireRootPeer(conn *net.UnixConn) error { return nil }
