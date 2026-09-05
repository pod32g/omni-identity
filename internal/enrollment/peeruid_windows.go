//go:build windows

package enrollment

import (
	"net"
	"os"
)

// peerUID on Windows: AF_UNIX sockets carry no peer credentials, and there
// is no uid to speak of (os.Getuid returns -1 for every process). The
// broker socket lives in the user's own profile directory
// (%LOCALAPPDATA%\Omni Access), whose NTFS ACL admits only that user, so
// reaching the socket at all is the credential; every caller is reported as
// the daemon's own user, which is what SignIn/Whoami record.
func peerUID(*net.UnixConn) (int, error) { return os.Getuid(), nil }
