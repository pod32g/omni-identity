package enrollment_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/enrollment"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
	"github.com/pod32g/omni-identity/internal/web"
)

// testIssuer runs a real Omni Identity server on a loopback port and returns
// its base URL, store, and a seeded user with a browser session.
type testIssuer struct {
	URL   string
	DB    *store.DB
	User  *model.User
	SID   string
	srv   *httptest.Server
	proxy *recordingTransport
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + l.Addr().String()
	db, err := store.Open(filepath.Join(t.TempDir(), "omni.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{}
	cfg.Server.PublicURL = base
	cfg.Security.Issuer = base
	cfg.Security.TokenTTL = 15 * time.Minute
	cfg.Security.RefreshTokenTTL = 720 * time.Hour
	cfg.Security.MaxFailedLogins = 5
	cfg.Security.LockoutDuration = 15 * time.Minute
	cfg.Security.RateLimitWindow = 15 * time.Minute
	cfg.Security.LoginIPMaxAttempts = 20
	cfg.Security.PasswordVerifyConcurrency = 4
	cfg.Security.MaxLoginUsernameBytes = 320
	cfg.Security.MaxLoginPasswordBytes = 1024
	cfg.Security.PasswordMinLength = 12
	cfg.Security.SessionLifetime = 12 * time.Hour
	cfg.Uploads.MaxLogoBytes = 512 * 1024
	handler, err := web.NewServer(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(handler)
	hs.Listener = l
	hs.Start()
	t.Cleanup(hs.Close)

	now := time.Now().UTC().Truncate(time.Second)
	u := &model.User{ID: uuid.NewString(), Username: "alice", Email: "alice@example.com", PasswordHash: "x", CreatedAt: now, UpdatedAt: now}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{ID: uuid.NewString(), UserID: u.ID, CSRFSecret: "c", CreatedAt: now, ExpiresAt: now.Add(time.Hour), AMR: "pwd"}
	if err := db.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return &testIssuer{URL: base, DB: db, User: u, SID: sess.ID, srv: hs}
}

// approvePending waits for a pending device code to appear and approves it as
// the seeded user through the real /device/confirm page.
func (ti *testIssuer) approvePending(t *testing.T) {
	t.Helper()
	// Codes already pending when we start belong to aborted earlier attempts;
	// only a grant created after this point is the caller's.
	stale := map[string]bool{}
	for _, c := range pendingUserCodes(t, ti.DB) {
		stale[c] = true
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var codes []string
		for _, c := range pendingUserCodes(t, ti.DB) {
			if !stale[c] {
				codes = append(codes, c)
			}
		}
		for _, userCode := range codes {
			form := url.Values{"csrf_token": {"csrf"}, "user_code": {userCode}, "action": {"allow"}}
			req, _ := http.NewRequest(http.MethodPost, ti.URL+"/device/confirm", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "omni_session", Value: ti.SID})
			req.AddCookie(&http.Cookie{Name: "omni_csrf", Value: "csrf"})
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), "Approved") {
				t.Fatalf("approve = %d: %s", resp.StatusCode, body)
			}
		}
		if len(codes) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no pending device code appeared")
}

// pendingUserCodes lists pending user codes (test-only helper over the store).
func pendingUserCodes(t *testing.T, db *store.DB) []string {
	t.Helper()
	return db.PendingUserCodesForTest(context.Background())
}

// recordingTransport captures every outbound request body so the test can
// prove no private key material leaves the endpoint (scenario 9).
type recordingTransport struct {
	mu     sync.Mutex
	bodies []string
	next   http.RoundTripper
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var buf bytes.Buffer
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		buf.Write(b)
		req.Body = io.NopCloser(bytes.NewReader(b))
	}
	for k, v := range req.Header {
		buf.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	rt.mu.Lock()
	rt.bodies = append(rt.bodies, buf.String())
	rt.mu.Unlock()
	return rt.next.RoundTrip(req)
}

func TestAgentEnrollRenewRotateUnenroll(t *testing.T) {
	ti := newTestIssuer(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	runDir := filepath.Join(t.TempDir(), "run")
	var out bytes.Buffer
	// Record all traffic the client sends.
	rec := &recordingTransport{next: http.DefaultTransport}
	agent := &enrollment.Agent{StateDir: stateDir, RuntimeDir: runDir, Out: &out, Transport: rec}
	cfg := enrollment.Config{Issuer: ti.URL, Name: "omni-vm", AllowInsecureHTTP: true}

	// Scenarios 7–12: enroll, approving concurrently as the user.
	done := make(chan error, 1)
	go func() {
		_, err := agent.Enroll(context.Background(), cfg)
		done <- err
	}()
	ti.approvePending(t)
	if err := <-done; err != nil {
		t.Fatalf("enroll: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Authenticate with Omni Identity") || !strings.Contains(out.String(), "Enrolled as alice") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
	st, err := enrollment.LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.OwnerSub != ti.User.ID || st.Status != "active" || st.Fingerprint == "" {
		t.Errorf("state = %+v", st)
	}
	key, err := enrollment.LoadKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(stateDir, "device.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o", fi.Mode().Perm())
	}
	// Scenario 9: the private key never left the machine.
	seed := base64.RawURLEncoding.EncodeToString(key.(interface{ Seed() []byte }).Seed())
	pemRaw, _ := os.ReadFile(filepath.Join(stateDir, "device.key"))
	rec.mu.Lock()
	for _, b := range rec.bodies {
		if strings.Contains(b, seed) || strings.Contains(b, strings.TrimSpace(string(pemRaw))) || strings.Contains(b, `"d":`) {
			t.Fatal("private key material was sent to the server")
		}
	}
	rec.mu.Unlock()
	dev, err := ti.DB.GetDevice(context.Background(), st.DeviceID)
	if err != nil || dev.Fingerprint != key.Fingerprint() || dev.OwnerUserID != ti.User.ID {
		t.Fatalf("server device = %+v err=%v", dev, err)
	}
	// Scenario 12: appears in the user's list.
	if devs, _ := ti.DB.ListDevicesForUser(context.Background(), ti.User.ID); len(devs) != 1 {
		t.Errorf("user devices = %d", len(devs))
	}

	// Scenarios 13–14: renew = prove possession, obtain a device token.
	st, tok, err := agent.Renew(context.Background())
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if tok.TokenType != "DPoP" || tok.DeviceID != st.DeviceID || st.Status != "active" {
		t.Errorf("renew: tok=%+v st=%+v", tok, st)
	}
	rt, err := enrollment.ReadStatus(runDir)
	if err != nil || rt.Status != "active" || !rt.IssuerReachable || rt.TokenExpiresAt.IsZero() {
		t.Errorf("status.json = %+v err=%v", rt, err)
	}
	// The device token is a bearer to nobody else: the API refuses it without
	// the key (covered server-side); here just confirm Me works through the client.
	_, _, client, err := agent.Open()
	if err != nil {
		t.Fatal(err)
	}
	me, err := client.Me(context.Background(), tok.AccessToken)
	if err != nil || me.ID != st.DeviceID || me.OwnerUsername != "alice" {
		t.Errorf("me = %+v err=%v", me, err)
	}

	// Rotation: new key on disk, old fingerprint retired server-side.
	oldFP := st.Fingerprint
	st, err = agent.RotateKey(context.Background())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newKey, _ := enrollment.LoadKey(stateDir)
	if st.Fingerprint == oldFP || newKey.Fingerprint() != st.Fingerprint {
		t.Errorf("rotation state: %+v key=%s", st, newKey.Fingerprint())
	}
	if _, _, err := agent.Renew(context.Background()); err != nil {
		t.Errorf("renew after rotation: %v", err)
	}

	// Scenarios 18–19: revocation by the user stops renewal; the agent records it.
	if err := ti.DB.RevokeDevice(context.Background(), st.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _, err = agent.Renew(context.Background())
	if err == nil || enrollment.IsConnectivityError(err) {
		t.Fatalf("renew after revoke should be refused, got %v", err)
	}
	if st.Status != "revoked" {
		t.Errorf("state after revoke = %+v", st)
	}
	if rt, _ := enrollment.ReadStatus(runDir); rt.Status != "revoked" || !rt.IssuerReachable {
		t.Errorf("status.json after revoke = %+v", rt)
	}

	// Unenroll wipes local state even though the server already revoked it.
	if err := agent.Unenroll(context.Background()); err != nil {
		t.Fatalf("unenroll: %v", err)
	}
	if _, err := enrollment.LoadState(stateDir); err != enrollment.ErrNotEnrolled {
		t.Error("state not removed")
	}
	if _, err := enrollment.LoadKey(stateDir); err != enrollment.ErrNoKey {
		t.Error("key not removed")
	}
}

func TestAgentDistinguishesUnreachableIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	runDir := filepath.Join(t.TempDir(), "run")
	agent := &enrollment.Agent{StateDir: stateDir, RuntimeDir: runDir, Out: io.Discard}
	done := make(chan error, 1)
	go func() {
		_, err := agent.Enroll(context.Background(), enrollment.Config{Issuer: ti.URL, AllowInsecureHTTP: true})
		done <- err
	}()
	ti.approvePending(t)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ti.srv.Close()
	st, _, err := agent.Renew(context.Background())
	if !enrollment.IsConnectivityError(err) {
		t.Fatalf("want connectivity error, got %v", err)
	}
	// Last known state is kept, never promoted to revoked on a network failure.
	if st.Status != "active" {
		t.Errorf("status after outage = %s", st.Status)
	}
	if rt, _ := enrollment.ReadStatus(runDir); rt.IssuerReachable || rt.Status != "active" {
		t.Errorf("status.json after outage = %+v", rt)
	}
}

func TestClientRefusesPlainHTTPWithoutOptIn(t *testing.T) {
	key, _, _ := enrollment.NewEphemeralKey()
	if _, err := enrollment.NewClient(enrollment.Options{Issuer: "http://id.example", Signer: key}); err == nil {
		t.Error("http issuer accepted without opt-in")
	}
	if _, err := enrollment.NewClient(enrollment.Options{Issuer: "ftp://id.example", Signer: key, AllowInsecureHTTP: true}); err == nil {
		t.Error("ftp issuer accepted")
	}
}

func TestLoadKeyRefusesWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := enrollment.GenerateKey(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.GenerateKey(dir, false); err == nil {
		t.Error("second GenerateKey should refuse to overwrite")
	}
	_ = os.Chmod(filepath.Join(dir, "device.key"), 0o644)
	if _, err := enrollment.LoadKey(dir); err == nil {
		t.Error("world-readable key accepted")
	}
}

var _ ed25519.PrivateKey // keep the import for the Seed() assertion above
