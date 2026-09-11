package enrollment_test

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/pop"
)

// The broker serves a local management agent that must act as the device:
// DEVICE returns a DPoP-bound device token for a registered audience and
// PROOF signs one proof with the device key — but only to a peer running as
// the daemon's own uid, and without any broker_audiences (those govern user
// tokens only).
func TestBrokerDeviceOperations(t *testing.T) {
	ti, agent := enrolledAgent(t, nil)
	now := time.Now().UTC()
	if err := ti.DB.CreateClient(context.Background(), &model.Client{ClientID: "omni-endpoint", Name: "endpoint", Type: model.ClientTypeConfidential,
		AllowedScopes: []string{"openid"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	short, _ := os.MkdirTemp("/tmp", "omni-dbrk")
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	agent.RuntimeDir = short
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := os.Getuid()
	fakePeer := func(*net.UnixConn) (int, error) { return peer, nil }
	// No audiences: the socket still comes up for device operations.
	go func() { _ = agent.ServeBroker(ctx, enrollment.BrokerPolicy{}, fakePeer, func(string, ...any) {}) }()
	time.Sleep(100 * time.Millisecond)

	tok, exp, err := enrollment.RequestDeviceToken(short, "omni-endpoint")
	if err != nil {
		t.Fatalf("DEVICE: %v", err)
	}
	if tok == "" || exp <= 0 {
		t.Fatalf("token = %q exp = %d", tok, exp)
	}
	claims, err := parseUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := enrollment.LoadState(agent.StateDir)
	if claims["aud"] != "omni-endpoint" || claims["sub"] != st.DeviceID || claims["token_use"] != "device" || claims["owner_sub"] != ti.User.ID {
		t.Errorf("claims = %v", claims)
	}
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf["jkt"] != st.Fingerprint {
		t.Errorf("cnf = %v, want jkt %s", claims["cnf"], st.Fingerprint)
	}
	// A second request within the lifetime reuses the cached token.
	if again, _, _ := enrollment.RequestDeviceToken(short, "omni-endpoint"); again != tok {
		t.Error("device token not reused")
	}
	// PROOF: a proof for a request to the management server, bound to the token.
	proof, err := enrollment.RequestProof(short, "POST", "https://endpoint.example/api/v1/agent/checkin", tok)
	if err != nil {
		t.Fatalf("PROOF: %v", err)
	}
	p, err := pop.VerifyProof(proof, pop.ProofOptions{HTM: "POST", HTU: "https://endpoint.example/api/v1/agent/checkin", AccessToken: tok})
	if err != nil {
		t.Fatalf("proof does not verify: %v", err)
	}
	if p.JKT != st.Fingerprint {
		t.Errorf("proof key %s != device key %s", p.JKT, st.Fingerprint)
	}
	if _, err := pop.VerifyProof(proof, pop.ProofOptions{HTM: "GET", HTU: "https://endpoint.example/api/v1/agent/checkin", AccessToken: tok}); err == nil {
		t.Error("proof verified for another method")
	}
	// A proof without a token is fine for unauthenticated requests.
	if _, err := enrollment.RequestProof(short, "GET", "https://endpoint.example/api/v1/meta", ""); err != nil {
		t.Errorf("unbound proof: %v", err)
	}
	// Unknown audience is refused by Omni.
	if _, _, err := enrollment.RequestDeviceToken(short, "nope"); err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Errorf("unknown audience: %v", err)
	}
	// Relative URLs and empty methods are refused locally.
	if _, err := enrollment.RequestProof(short, "GET", "/relative", ""); err == nil {
		t.Error("relative url accepted")
	}
	// Another uid gets nothing, for either operation.
	peer = os.Getuid() + 1
	if _, _, err := enrollment.RequestDeviceToken(short, "omni-endpoint"); err == nil || !strings.Contains(err.Error(), "own uid") {
		t.Errorf("foreign uid DEVICE: %v", err)
	}
	if _, err := enrollment.RequestProof(short, "GET", "https://endpoint.example/", ""); err == nil || !strings.Contains(err.Error(), "own uid") {
		t.Errorf("foreign uid PROOF: %v", err)
	}
	// The user-token paths are unaffected by these operations: with no
	// audiences configured, TOKEN and PAT are refused as before.
	peer = 501
	if _, _, err := enrollment.RequestBrokerToken(short, "omni-endpoint", ""); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("user token without audiences: %v", err)
	}
	conn, err := net.Dial("unix", filepath.Join(short, enrollment.BrokerSocketName))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(`PAT {"action":"list"}` + "\n"))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(line, "broker is disabled") {
		t.Errorf("PAT without audiences: %q", line)
	}
}
