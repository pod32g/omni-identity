//go:build windows

package enrollment

import (
	"errors"
	"os/user"
)

func desktopUser() *user.User { return nil }

func openAsUser(*user.User, string) error { return errors.New("not supported on this platform") }
