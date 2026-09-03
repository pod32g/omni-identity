package enrollment_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
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

// fakeProv is an in-memory account database.
type fakeProv struct {
	users map[string]int
	uids  map[int]bool
}

func newFakeProv() *fakeProv {
	return &fakeProv{users: map[string]int{"root": 0, "omni-recovery": 1000}, uids: map[int]bool{0: true, 1000: true}}
}
func (p *fakeProv) Lookup(name string) (int, bool, error) {
	uid, ok := p.users[name]
	return uid, ok, nil
}
func (p *fakeProv) UIDInUse(uid int) (bool, error) { return p.uids[uid], nil }
func (p *fakeProv) Create(name string, uid, gid int, home, shell, gecos string) error {
	p.users[name] = uid
	p.uids[uid] = true
	return nil
}

func enrolledAgent(t *testing.T, prov enrollment.Provisioner) (*testIssuer, *enrollment.Agent) {
	t.Helper()
	ti := newTestIssuer(t)
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "state"), RuntimeDir: filepath.Join(t.TempDir(), "run"), Out: io.Discard, Provisioner: prov}
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

// Scenarios 26–27: online login through Omni provisions the local account.
func TestLinuxOnlineLoginProvisionsAndCaches(t *testing.T) {
	prov := newFakeProv()
	ti, agent := enrolledAgent(t, prov)
	pol := enrollment.DefaultLoginPolicy

	// Enrollment pre-provisions the owner (sshd needs the account to exist
	// before PAM runs) with a cache entry that cannot yet log in offline.
	seededUID, ok := prov.users["alice"]
	if !ok || seededUID < 200000 || seededUID >= 300000 {
		t.Fatalf("owner not pre-provisioned: uid=%d ok=%v", seededUID, ok)
	}
	if seeded, _ := agent.LoadUserCache("alice"); seeded == nil || seeded.SecretHash != "" || seeded.Sub != ti.User.ID {
		t.Fatalf("seeded cache = %+v", seeded)
	}
	// With no scripted answers the conversation aborts at the first prompt:
	// that prompt must be the online sign-in link, not the local-password one.
	offline := &scriptConv{}
	if v := agent.Login(context.Background(), offline, enrollment.LoginContext{Username: "alice"}, prov, pol); v == enrollment.VerdictOK || strings.Contains(offline.transcript(), "Local password") {
		t.Fatalf("offline login offered before any online login: %d\n%s", v, offline.transcript())
	}

	conv := &scriptConv{answers: []string{"", "hunter2xyz", "hunter2xyz"}} // Enter, local pw, retype
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice", Service: "sshd"}, prov, pol)
	}()
	ti.approvePending(t)
	if v := <-verdict; v != enrollment.VerdictOK {
		t.Fatalf("verdict = %d\n%s", v, conv.transcript())
	}
	tr := conv.transcript()
	if !strings.Contains(tr, "/device?user_code=") || !strings.Contains(tr, "New local password") {
		t.Errorf("transcript:\n%s", tr)
	}
	uid := prov.users["alice"]
	if uid != seededUID {
		t.Errorf("uid changed at login: %d vs %d", uid, seededUID)
	}
	uc, err := agent.LoadUserCache("alice")
	if err != nil || uc == nil {
		t.Fatalf("cache: %+v err=%v", uc, err)
	}
	if uc.Sub != ti.User.ID || uc.UID != uid || uc.SecretHash == "" || uc.RefreshToken == "" || uc.AMR != "pwd" || uc.DeviceID == "" {
		t.Errorf("cache = %+v", uc)
	}
	if strings.Contains(uc.SecretHash, "hunter2xyz") {
		t.Error("local password stored in clear")
	}
	// The pending device grant was device-bound: the server recorded the device
	// on the audit trail of the approval.
	dev, _ := ti.DB.GetDevice(context.Background(), uc.DeviceID)
	if dev == nil || dev.LastSeenAt.IsZero() {
		t.Error("device not seen during login")
	}

	// Scenarios 28–31: Omni unreachable → offline login with the local password.
	ti.srv.Close()
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol); v != enrollment.VerdictOK {
		t.Fatalf("offline verdict = %d\n%s", v, conv.transcript())
	}
	if !strings.Contains(conv.transcript(), "Local password") {
		t.Errorf("offline transcript:\n%s", conv.transcript())
	}
	conv = &scriptConv{answers: []string{"wrong-password"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol); v != enrollment.VerdictFail {
		t.Errorf("wrong local password accepted")
	}
	// Empty answer asks Omni, which is down: a clear error, no session.
	conv = &scriptConv{answers: []string{""}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol); v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "unreachable") {
		t.Errorf("online attempt while down: %d\n%s", v, conv.transcript())
	}
	// Scenario 32: break-glass / local accounts are not ours.
	if v := agent.Login(context.Background(), &scriptConv{}, enrollment.LoginContext{Username: "omni-recovery"}, prov, pol); v != enrollment.VerdictIgnore {
		t.Errorf("omni-recovery verdict = %d, want ignore", v)
	}
	if v := agent.Login(context.Background(), &scriptConv{}, enrollment.LoginContext{Username: "root"}, prov, pol); v != enrollment.VerdictIgnore {
		t.Errorf("root verdict = %d, want ignore", v)
	}
	// Offline validity window is enforced.
	uc.LastTrustRefresh = time.Now().Add(-8 * 24 * time.Hour)
	_ = agent.SaveUserCache(uc)
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol); v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "expired") {
		t.Errorf("expired offline window accepted: %d\n%s", v, conv.transcript())
	}
}

func TestLinuxLoginRejectsApprovalByAnotherUser(t *testing.T) {
	prov := newFakeProv()
	ti, agent := enrolledAgent(t, prov)
	conv := &scriptConv{answers: []string{""}}
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "bob"}, prov, enrollment.DefaultLoginPolicy)
	}()
	ti.approvePending(t) // approved as alice
	if v := <-verdict; v != enrollment.VerdictFail || !strings.Contains(conv.transcript(), "different account") {
		t.Errorf("verdict = %d\n%s", v, conv.transcript())
	}
	if _, ok := prov.users["bob"]; ok {
		t.Error("bob was provisioned without a matching approval")
	}
}

// Scenarios 33–35: trust refresh on reconnect, and revocation propagation.
func TestLinuxTrustRefreshAndRevocation(t *testing.T) {
	prov := newFakeProv()
	ti, agent := enrolledAgent(t, prov)
	pol := enrollment.DefaultLoginPolicy
	conv := &scriptConv{answers: []string{"", "hunter2xyz", "hunter2xyz"}}
	verdict := make(chan enrollment.Verdict, 1)
	go func() {
		verdict <- agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol)
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
	if agent.Account("alice", prov, pol) != enrollment.VerdictOK {
		t.Error("account should be ok")
	}

	// The user revokes the device in Omni; the next refresh marks the cache.
	if err := ti.DB.RevokeDevice(context.Background(), after.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	agent.RefreshUsers(context.Background(), client, func(string, ...any) {})
	uc, _ := agent.LoadUserCache("alice")
	if !uc.Revoked || uc.RefreshToken != "" {
		t.Fatalf("cache not revoked: %+v", uc)
	}
	conv = &scriptConv{answers: []string{"hunter2xyz"}}
	if v := agent.Login(context.Background(), conv, enrollment.LoginContext{Username: "alice"}, prov, pol); v != enrollment.VerdictFail {
		t.Errorf("offline login after revocation accepted\n%s", conv.transcript())
	}
	if agent.Account("alice", prov, pol) != enrollment.VerdictFail {
		t.Error("account should fail after revocation")
	}
	// A transport failure never revokes anything.
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
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "s"), RuntimeDir: filepath.Join(t.TempDir(), "r"), Out: io.Discard}
	// A cached, offline-capable user. The secret hash comes from a real login
	// path; hash it through the same code by saving then verifying via Login.
	uc := &enrollment.UserCache{Username: "alice", Sub: "sub", UID: 200001, GID: 200001, Home: "/home/alice",
		LastTrustRefresh: time.Now(), DeviceID: "d"}
	uc.SecretHash = enrollment.HashLocalSecretForTest("correct horse")
	if err := agent.SaveUserCache(uc); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = agent.ServePAM(ctx, newFakeProv(), enrollment.DefaultLoginPolicy, func(string, ...any) {}) }()
	sock := filepath.Join(agent.RuntimeDir, enrollment.PAMSocketName)
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
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
	// Second connection: account check and an unknown user.
	conn2, _ := net.Dial("unix", sock)
	defer conn2.Close()
	_, _ = conn2.Write([]byte("ACCT alice sshd\n"))
	line, _ = bufio.NewReader(conn2).ReadString('\n')
	if strings.TrimSpace(line) != "R OK alice" {
		t.Errorf("acct = %q", line)
	}
	conn3, _ := net.Dial("unix", sock)
	defer conn3.Close()
	_, _ = conn3.Write([]byte("AUTH root login -\n"))
	line, _ = bufio.NewReader(conn3).ReadString('\n')
	if strings.TrimSpace(line) != "R IGNORE" {
		t.Errorf("root = %q", line)
	}
}
