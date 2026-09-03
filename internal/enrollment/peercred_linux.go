//go:build linux

package enrollment

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// requireRootPeer enforces that the connecting process runs as uid 0
// (SO_PEERCRED). The PAM stack of login/sshd/gdm/sudo runs as root.
func requireRootPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if cred.Uid != 0 {
		return errors.New("peer is not root")
	}
	return nil
}
