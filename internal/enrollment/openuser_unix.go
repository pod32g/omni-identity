//go:build !windows

package enrollment

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// desktopUser returns the person who invoked this root process through sudo
// (SUDO_USER) or pkexec (PKEXEC_UID), or nil when not running as root on
// their behalf.
func desktopUser() *user.User {
	if os.Geteuid() != 0 {
		return nil
	}
	var u *user.User
	if name := os.Getenv("SUDO_USER"); name != "" {
		u, _ = user.Lookup(name)
	} else if id := os.Getenv("PKEXEC_UID"); id != "" {
		u, _ = user.LookupId(id)
	}
	if u == nil || u.Uid == "0" {
		return nil
	}
	return u
}

// openAsUser starts xdg-open with the desktop user's credentials and session
// environment so the page opens in their browser, not root's.
func openAsUser(u *user.User, target string) error {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return err
	}
	var groups []uint32
	if ids, err := u.GroupIds(); err == nil {
		for _, g := range ids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	cmd := exec.Command("xdg-open", target)
	cmd.Dir = u.HomeDir
	cmd.Env = userSessionEnv(u, os.Environ(), exists)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
	return cmd.Start()
}
