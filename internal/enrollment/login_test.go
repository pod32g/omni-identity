package enrollment_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
	"github.com/pod32g/omni-identity/internal/model"
)

// scriptConv is a scripted PAM conversation.
type scriptConv struct {
	answers []string
	log     []string
}

func (c *scriptConv) Info(t string)  { c.log = append(c.log, "I:"+t) }
func (c *scriptConv) Error(t string) { c.log = append(c.log, "W:"+t) }
func (c *scriptConv) Prompt(t string, echo bool) (string, error) {
	c.log = append(c.log, "P:"+t)
	if len(c.answers) == 0 {
		return "", errors.New("no scripted answer")
	}
	a := c.answers[0]
	c.answers = c.answers[1:]
	return a, nil
}
func (c *scriptConv) transcript() string { return strings.Join(c.log, "\n") }

// fakeAccounts is an in-memory /etc/passwd.
type fakeAccounts struct{ local map[string]int }

func newFakeAccounts() *fakeAccounts {
	return &fakeAccounts{local: map[string]int{"root": 0, "omni-recovery": 1000}}
}
func (f *fakeAccounts) IsLocalAccount(name string) (bool, error) {
	_, ok := f.local[name]
	return ok, nil
}
func (f *fakeAccounts) UIDInUse(uid int) (bool, error) {
	for _, u := range f.local {
		if u == uid {
			return true, nil
		}
	}
	return false, nil
}

func enrolledAgent(t *testing.T, accounts enrollment.LocalAccounts) (*testIssuer, *enrollment.Agent) {
	t.Helper()
	ti := newTestIssuer(t)
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "state"), RuntimeDir: filepath.Join(t.TempDir(), "run"),
		Out: io.Discard, Accounts: accounts, NoHome: true}
	done := make(chan error, 1)
	go func() {
		_, err := agent.Enroll(context.Background(), enrollment.Config{Issuer: ti.URL, AllowInsecureHTTP: true})
		done <- err
	}()
	ti.approvePending(t)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return ti, agent
}

// Scenarios 26–27: online login through Omni establishes the local identity.
func TestLinuxOnlineLoginProvisionsAndCaches(t *testing.T) {
	accounts := newFakeAccounts()
	ti, agent := enrolledAgent(t, accounts)
	pol := enrollment.DefaultLoginPolicy

	// Enrollment records the owner's identity (sshd needs it before PAM runs)
	// without a local password, so offline login is not yet possible.
	seeded, _ := agent.LoadUserCache("alice")
	if seeded == nil || seeded.SecretHash != "" || seeded.Sub != ti.User.ID || seeded.UID < 200000 || seeded.UID >= 300000 {
		t.Fatalf("seeded identity = %+v", seeded)
	}
	offline := &scriptConv{}
	if v := agent.Login(context.Background(), offline, enrollment.LoginContext{Username: "alice"}, accounts, pol); v == enrollment.VerdictOK || strings.Contains(offline.transcript(), "Local password") {
		t.Fatalf("offline login offered before any online login: %d\n%s", v, offline.transcript())
	}

	conv := &scriptConv{answers: []string{"", "hunter2xyz", "hunter2xyz"}} // Enter, local pw, retype
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice", Service: "sshd"}, accounts, pol)
	}()
	ti.approvePending(t)
	if v := <-verdict; v != enrollment.VerdictOK {
		t.Fatalf("verdict = %d\n%s", v, conv.transcript())
	}
	tr := conv.transcript()
	if !strings.Contains(tr, "/device?user_code=") || !strings.Contains(tr, "New local password") {
		t.Errorf("transcript:\n%s", tr)
	}
	uc, err := agent.LoadUserCache("alice")
	if err != nil || uc == nil {
		t.Fatalf("cache: %+v err=%v", uc, err)
	}
	if uc.UID != seeded.UID || uc.SecretHash == "" || uc.RefreshToken == "" || uc.AMR != "pwd" || uc.DeviceID == "" {
		t.Errorf("cache = %+v", uc)
	}
	if strings.Contains(uc.SecretHash, "hunter2xyz") {
		t.Error("local password stored in clear")
	}
	dev, _ := ti.DB.GetDevice(context.Background(), uc.DeviceID)
	if dev == nil || dev.LastSeenAt.IsZero() {
		t.Error("device not seen during login")
	}

	// Scenarios 28–31: Omni unreachable → offline login with the local password.
	ti.srv.Close()
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol); v != enrollment.VerdictOK {
		t.Fatalf("offline verdict = %d\n%s", v, conv.transcript())
	}
	conv = &scriptConv{answers: []string{"wrong-password"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol); v != enrollment.VerdictFail {
		t.Errorf("wrong local password accepted")
	}
	conv = &scriptConv{answers: []string{""}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol); v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "unreachable") {
		t.Errorf("online attempt while down: %d\n%s", v, conv.transcript())
	}
	// Scenario 32: break-glass / local accounts are not ours.
	for _, name := range []string{"omni-recovery", "root"} {
		if v := agent.Login(context.Background(), &scriptConv{}, enrollment.LoginContext{Username: name}, accounts, pol); v != enrollment.VerdictIgnore {
			t.Errorf("%s verdict = %d, want ignore", name, v)
		}
	}
	// Offline validity window is enforced.
	uc.LastTrustRefresh = time.Now().Add(-8 * 24 * time.Hour)
	_ = agent.SaveUserCache(uc)
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol); v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "expired") {
		t.Errorf("expired offline window accepted: %d\n%s", v, conv.transcript())
	}
}

func TestLinuxLoginRejectsApprovalByAnotherUser(t *testing.T) {
	accounts := newFakeAccounts()
	ti, agent := enrolledAgent(t, accounts)
	conv := &scriptConv{answers: []string{""}}
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "bob"}, accounts, enrollment.DefaultLoginPolicy)
	}()
	ti.approvePending(t) // approved as alice
	if v := <-verdict; v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "different account") {
		t.Errorf("verdict = %d\n%s", v, conv.transcript())
	}
	if uc, _ := agent.LoadUserCache("bob"); uc != nil {
		t.Error("bob got an identity without a matching approval")
	}
}

// Scenarios 33–35: trust refresh on reconnect, and revocation propagation.
func TestLinuxTrustRefreshAndRevocation(t *testing.T) {
	accounts := newFakeAccounts()
	ti, agent := enrolledAgent(t, accounts)
	pol := enrollment.DefaultLoginPolicy
	conv := &scriptConv{answers: []string{"", "hunter2xyz", "hunter2xyz"}}
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol)
	}()
	ti.approvePending(t)
	if v := <-verdict; v != enrollment.VerdictOK {
		t.Fatalf("login: %d\n%s", v, conv.transcript())
	}
	_, _, client, err := agent.Open()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := agent.LoadUserCache("alice")
	time.Sleep(1100 * time.Millisecond)
	agent.RefreshUsers(context.Background(), client, func(string, ...any) {})
	after, _ := agent.LoadUserCache("alice")
	if !after.LastTrustRefresh.After(before.LastTrustRefresh) || after.RefreshToken == before.RefreshToken {
		t.Errorf("trust refresh did not rotate: before=%v after=%v", before.LastTrustRefresh, after.LastTrustRefresh)
	}
	if agent.Account("alice", accounts, pol) != enrollment.VerdictOK {
		t.Error("account should be ok")
	}
	if err := ti.DB.RevokeDevice(context.Background(), after.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	agent.RefreshUsers(context.Background(), client, func(string, ...any) {})
	uc, _ := agent.LoadUserCache("alice")
	if !uc.Revoked || uc.RefreshToken != "" {
		t.Fatalf("cache not revoked: %+v", uc)
	}
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, pol); v != enrollment.VerdictFail {
		t.Errorf("offline login after revocation accepted\n%s", conv.transcript())
	}
	if agent.Account("alice", accounts, pol) != enrollment.VerdictFail {
		t.Error("account should fail after revocation")
	}
	ti.srv.Close()
	fresh := &enrollment.UserCache{Username: "carol", Sub: "s", RefreshToken: "rt", LastTrustRefresh: time.Now()}
	_ = agent.SaveUserCache(fresh)
	agent.RefreshUsers(context.Background(), client, func(string, ...any) {})
	if c, _ := agent.LoadUserCache("carol"); c.Revoked {
		t.Error("connectivity failure marked the user revoked")
	}
}

// The PAM socket protocol end to end (offline path, no server needed).
func TestPAMSocketProtocol(t *testing.T) {
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "s"), RuntimeDir: filepath.Join(t.TempDir(), "r"), Out: io.Discard, NoHome: true}
	uc := &enrollment.UserCache{Username: "alice", Sub: "sub", UID: 200001, GID: 200001, Home: "/home/alice",
		LastTrustRefresh: time.Now(), DeviceID: "d"}
	uc.SecretHash = enrollment.HashLocalSecretForTest("correct horse")
	if err := agent.SaveUserCache(uc); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = agent.ServePAM(ctx, newFakeAccounts(), enrollment.DefaultLoginPolicy, func(string, ...any) {})
	}()
	sock := filepath.Join(agent.RuntimeDir, enrollment.PAMSocketName)
	conn := dialRetry(t, sock)
	defer conn.Close()
	r := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("AUTH alice sshd 10.0.0.5\n"))
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "P Local password") {
		t.Fatalf("first line = %q", line)
	}
	_, _ = conn.Write([]byte("A correct horse\n"))
	line, _ = r.ReadString('\n')
	if strings.TrimSpace(line) != "R OK alice" {
		t.Fatalf("verdict = %q", line)
	}
	conn2 := dialRetry(t, sock)
	defer conn2.Close()
	_, _ = conn2.Write([]byte("ACCT alice sshd\n"))
	line, _ = bufio.NewReader(conn2).ReadString('\n')
	if strings.TrimSpace(line) != "R OK alice" {
		t.Errorf("acct = %q", line)
	}
	conn3 := dialRetry(t, sock)
	defer conn3.Close()
	_, _ = conn3.Write([]byte("AUTH root login -\n"))
	line, _ = bufio.NewReader(conn3).ReadString('\n')
	if strings.TrimSpace(line) != "R IGNORE" {
		t.Errorf("root = %q", line)
	}
}

// The NSS identity socket: cached identities, uid lookups, local-account
// shadowing, and the online lookup for a never-seen Omni user.
func TestNSSSocketResolvesIdentities(t *testing.T) {
	accounts := newFakeAccounts()
	ti, agent := enrolledAgent(t, accounts)
	// bob exists in Omni but has never touched this machine.
	bob := seedIssuerUser(t, ti, "bob")
	// Unix socket paths are limited to ~104 bytes on macOS; t.TempDir is longer.
	short, err := os.MkdirTemp("/tmp", "omni-nss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	agent.RuntimeDir = short
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.ServeNSS(ctx, accounts, enrollment.DefaultLoginPolicy, func(string, ...any) {}) }()
	sock := filepath.Join(agent.RuntimeDir, enrollment.NSSSocketName)
	ask := func(q string) string {
		c := dialRetry(t, sock)
		defer c.Close()
		_, _ = c.Write([]byte(q + "\n"))
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	alice, _ := agent.LoadUserCache("alice")
	if got := ask("PWNAM alice"); !strings.HasPrefix(got, "PW alice "+itoa(alice.UID)+" "+itoa(alice.UID)+" /home/alice /bin/bash Omni Identity ") {
		t.Errorf("PWNAM alice = %q", got)
	}
	if got := ask("PWUID " + itoa(alice.UID)); !strings.HasPrefix(got, "PW alice ") {
		t.Errorf("PWUID = %q", got)
	}
	if got := ask("GRNAM alice"); got != "GR alice "+itoa(alice.UID) {
		t.Errorf("GRNAM = %q", got)
	}
	if got := ask("GRGID " + itoa(alice.UID)); got != "GR alice "+itoa(alice.UID) {
		t.Errorf("GRGID = %q", got)
	}
	// Online lookup for bob creates a cached identity (no secret).
	got := ask("PWNAM bob")
	if !strings.HasPrefix(got, "PW bob ") {
		t.Fatalf("PWNAM bob = %q", got)
	}
	uc, _ := agent.LoadUserCache("bob")
	if uc == nil || uc.Sub != bob || uc.SecretHash != "" || uc.UID == alice.UID {
		t.Errorf("bob identity = %+v", uc)
	}
	// Local accounts, unknown users, junk, and root's uid are never answered.
	for _, q := range []string{"PWNAM root", "PWNAM omni-recovery", "PWNAM nobody-here", "PWNAM Bad Name", "PWUID 0", "PWUID 1000", "GRGID 0", "HELLO"} {
		if got := ask(q); got != "NONE" {
			t.Errorf("%s = %q, want NONE", q, got)
		}
	}
	// Offline: cached identities still resolve, unknown names do not hang.
	ti.srv.Close()
	if got := ask("PWNAM bob"); !strings.HasPrefix(got, "PW bob ") {
		t.Errorf("offline PWNAM bob = %q", got)
	}
	start := time.Now()
	if got := ask("PWNAM dave"); got != "NONE" || time.Since(start) > 8*time.Second {
		t.Errorf("offline unknown = %q in %s", got, time.Since(start))
	}
}

func dialRetry(t *testing.T, sock string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("unix", sock); err == nil {
			return conn
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }

// The local token broker: a signed-in user's process gets an audience-bound
// token; others get nothing.
func TestBrokerIssuesAudienceTokensForSignedInUsers(t *testing.T) {
	accounts := newFakeAccounts()
	ti, agent := enrolledAgent(t, accounts)
	// A registered local application.
	now := time.Now().UTC()
	if err := ti.DB.CreateClient(context.Background(), &model.Client{ClientID: "omni-metrics", Name: "metrics", Type: model.ClientTypeConfidential,
		AllowedScopes: []string{"openid", "email"}, RedirectURIs: []string{"https://m/cb"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	// alice signs in online so a device-bound refresh token is cached.
	conv := &scriptConv{answers: []string{"", "hunter2xyz", "hunter2xyz"}}
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, accounts, enrollment.DefaultLoginPolicy)
	}()
	ti.approvePending(t)
	if v := <-verdict; v != enrollment.VerdictOK {
		t.Fatalf("login: %d\n%s", v, conv.transcript())
	}
	alice, _ := agent.LoadUserCache("alice")

	short, _ := os.MkdirTemp("/tmp", "omni-brk")
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	agent.RuntimeDir = short
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var peer int
	fakePeer := func(*net.UnixConn) (int, error) { return peer, nil }
	pol := enrollment.BrokerPolicy{Audiences: []string{"omni-metrics"}}
	go func() { _ = agent.ServeBroker(ctx, pol, fakePeer, func(string, ...any) {}) }()
	time.Sleep(100 * time.Millisecond)

	peer = alice.UID
	tok, exp, err := enrollment.RequestBrokerToken(short, "omni-metrics", "")
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	if exp <= 0 || tok == "" {
		t.Fatalf("token = %q exp=%d", tok, exp)
	}
	claims, err := parseUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != ti.User.ID || claims["aud"] != "omni-metrics" || claims["device_id"] != alice.DeviceID || claims["act"].(map[string]any)["sub"] != alice.DeviceID {
		t.Errorf("claims = %v", claims)
	}
	if _, _, err := enrollment.RequestBrokerToken(short, "jellyfin", ""); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("disallowed audience: %v", err)
	}
	peer = 0
	if _, _, err := enrollment.RequestBrokerToken(short, "omni-metrics", ""); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("root caller: %v", err)
	}
	peer = alice.UID + 7 // some other local uid, never signed in
	if _, _, err := enrollment.RequestBrokerToken(short, "omni-metrics", ""); err == nil || !strings.Contains(err.Error(), "not a signed-in") {
		t.Errorf("stranger caller: %v", err)
	}
	// Revocation closes the broker for that user.
	alice.Revoked = true
	_ = agent.SaveUserCache(alice)
	peer = alice.UID
	if _, _, err := enrollment.RequestBrokerToken(short, "omni-metrics", ""); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked caller: %v", err)
	}
}

func parseUnverified(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a jwt")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}
