//go:build darwin

package enrollment

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A local connection is attributed to the connecting process's own uid.
func TestPeerUIDDarwin(t *testing.T) {
	// Unix socket paths are limited to ~104 bytes on macOS; t.TempDir is longer.
	dir, err := os.MkdirTemp("/tmp", "omni-peer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "peer.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	uid, err := peerUID(server.(*net.UnixConn))
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if uid != os.Getuid() {
		t.Errorf("peer uid = %d, want %d", uid, os.Getuid())
	}
}
