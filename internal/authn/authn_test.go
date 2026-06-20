package authn

import (
	"context"
	"testing"
)

type stubConn struct{}

func (stubConn) ID() string { return "stub" }
func (stubConn) Login(context.Context, string, string) (Identity, bool, error) {
	return Identity{Connector: "stub", Username: "x"}, true, nil
}

// TestPasswordConnectorContract pins the interface shape: a connector is
// satisfiable and Login's (Identity, ok, err) tuple carries what callers expect.
func TestPasswordConnectorContract(t *testing.T) {
	var c PasswordConnector = stubConn{}
	if c.ID() != "stub" {
		t.Fatalf("ID() = %q", c.ID())
	}
	id, ok, err := c.Login(context.Background(), "x", "y")
	if err != nil || !ok || id.Connector != "stub" || id.Username != "x" {
		t.Fatalf("bad contract: %+v ok=%v err=%v", id, ok, err)
	}
}
