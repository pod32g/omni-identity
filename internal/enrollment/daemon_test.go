package enrollment_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
)

// Off Linux the daemon runs without the login integration: no PAM/NSS
// sockets, no account provisioning, but the token broker still comes up.
func TestDaemonServesBrokerWithoutPAM(t *testing.T) {
	_, agent := enrolledAgent(t, nil)
	// Unix socket paths are limited to ~104 bytes on macOS; t.TempDir is longer.
	short, err := os.MkdirTemp("/tmp", "omni-dmn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	agent.RuntimeDir = short
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.RunDaemon(ctx, enrollment.DaemonOptions{
			ServePAM: false, RefreshEvery: 50 * time.Millisecond,
			Broker: enrollment.BrokerPolicy{Audiences: []string{"omni-metrics"}},
		}, func(string, ...any) {})
	}()
	broker := filepath.Join(short, enrollment.BrokerSocketName)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(broker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Give the renewal loop a cycle so status.json exists too.
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, err := enrollment.ReadStatus(short); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status.json never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, name := range []string{enrollment.PAMSocketName, enrollment.NSSSocketName} {
		if _, err := os.Stat(filepath.Join(short, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists without ServePAM (err=%v)", name, err)
		}
	}
	// No owner account was pre-provisioned either.
	if uc, _ := agent.LoadUserCache("alice"); uc != nil {
		t.Errorf("owner identity provisioned without ServePAM: %+v", uc)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("daemon exited with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop after cancel")
	}
}
