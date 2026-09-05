//go:build !windows

package enrollment

import (
	"fmt"
	"os"
)

// protectKeyFile is the identity on Unix: the 0600 mode guards the file.
func protectKeyFile(pemBytes []byte) ([]byte, error) { return pemBytes, nil }

func unprotectKeyFile(raw []byte) ([]byte, error) { return raw, nil }

// checkKeyFileMode refuses a key readable by other users.
func checkKeyFileMode(path string) error {
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by others (mode %04o); refusing to use it", path, fi.Mode().Perm())
	}
	return nil
}
