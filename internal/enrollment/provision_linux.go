//go:build linux

package enrollment

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
)

// SystemProvisioner creates local accounts with useradd (shadow-utils). The
// password field is left locked ("!") so only pam_omni can authenticate them.
type SystemProvisioner struct{}

func (SystemProvisioner) Lookup(name string) (int, bool, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if _, ok := err.(user.UnknownUserError); ok || errorsAs(err, &unknown) {
			return 0, false, nil
		}
		return 0, false, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	return uid, true, nil
}

func (SystemProvisioner) UIDInUse(uid int) (bool, error) {
	_, err := user.LookupId(strconv.Itoa(uid))
	if err == nil {
		return true, nil
	}
	if _, ok := err.(user.UnknownUserIdError); ok {
		return false, nil
	}
	return false, err
}

func (SystemProvisioner) Create(name string, uid, gid int, home, shell, gecos string) error {
	// groupadd first so the private group gets the same numeric id.
	if out, err := exec.Command("groupadd", "-g", strconv.Itoa(gid), name).CombinedOutput(); err != nil {
		return fmt.Errorf("groupadd: %s", string(out))
	}
	args := []string{"-m", "-u", strconv.Itoa(uid), "-g", strconv.Itoa(gid), "-d", home, "-s", shell, "-c", gecos, name}
	if out, err := exec.Command("useradd", args...).CombinedOutput(); err != nil {
		_ = exec.Command("groupdel", name).Run()
		return fmt.Errorf("useradd: %s", string(out))
	}
	return nil
}

func errorsAs(err error, target *user.UnknownUserError) bool {
	_, ok := err.(user.UnknownUserError)
	return ok
}
