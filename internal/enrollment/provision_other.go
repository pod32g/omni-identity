//go:build !linux

package enrollment

import "errors"

// SystemProvisioner is only implemented on Linux; elsewhere the daemon can
// still run its enrollment duties but cannot create accounts.
type SystemProvisioner struct{}

func (SystemProvisioner) Lookup(string) (int, bool, error) { return 0, false, nil }
func (SystemProvisioner) UIDInUse(int) (bool, error)       { return false, nil }
func (SystemProvisioner) Create(string, int, int, string, string, string) error {
	return errors.New("local account provisioning is only supported on Linux")
}
