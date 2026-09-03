package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

// fakeAuthenticator is a minimal software FIDO2 authenticator producing
// "none"-attested P-256 credentials and assertions, enough to exercise the
// server's full WebAuthn ceremonies without a browser.
type fakeAuthenticator struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	counter    uint32
	uv         bool
	rpID       string
	origin     string
}

func newFakeAuthenticator(t *testing.T, uv bool) *fakeAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &fakeAuthenticator{key: key, credID: id, uv: uv, rpID: "localhost", origin: "http://localhost:8080"}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *fakeAuthenticator) flags(attested bool) byte {
	f := byte(0x01) // UP
	if a.uv {
		f |= 0x04 // UV
	}
	if attested {
		f |= 0x40 // AT
	}
	return f
}

func (a *fakeAuthenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin})
	return b
}

// attest answers a registration challenge.
func (a *fakeAuthenticator) attest(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	enc, _ := cbor.CanonicalEncOptions().EncMode()
	cose, err := enc.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: a.key.PublicKey.X.FillBytes(make([]byte, 32)),
		-3: a.key.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(a.rpID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, a.flags(true))
	authData = binary.BigEndian.AppendUint32(authData, a.counter)
	authData = append(authData, make([]byte, 16)...) // aaguid
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)
	attObj, err := enc.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(a.clientData("webauthn.create", challenge)),
			"attestationObject": b64u(attObj),
		},
	})
	return resp
}

// assert answers an authentication challenge.
func (a *fakeAuthenticator) assert(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	a.counter++
	rpHash := sha256.Sum256([]byte(a.rpID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, a.flags(false))
	authData = binary.BigEndian.AppendUint32(authData, a.counter)
	cd := a.clientData("webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	r := map[string]any{
		"clientDataJSON": b64u(cd), "authenticatorData": b64u(authData), "signature": b64u(sig),
	}
	if a.userHandle != nil {
		r["userHandle"] = b64u(a.userHandle)
	}
	resp, _ := json.Marshal(map[string]any{"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key", "response": r})
	return resp
}

func jsonReq(path string, body any, cookies ...*http.Cookie) *http.Request {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func csrfCookie() *http.Cookie { return &http.Cookie{Name: "omni_csrf", Value: "csrf-1"} }

// registerPasskey runs the account registration ceremony for user.
func registerPasskey(t *testing.T, srv *Server, user *model.User, fa *fakeAuthenticator, name string) string {
	t.Helper()
	sid := startSession(t, srv, user.ID)
	sc := &http.Cookie{Name: "omni_session", Value: sid}
	rr := do(srv, jsonReq("/account/passkeys/begin", map[string]string{"csrf_token": "csrf-1"}, sc, csrfCookie()))
	if rr.Code != http.StatusOK {
		t.Fatalf("begin = %d: %s", rr.Code, rr.Body.String())
	}
	var begin struct {
		Ceremony string `json:"ceremony"`
		Options  struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				User      struct {
					ID string `json:"id"`
				} `json:"user"`
				ExcludeCredentials []map[string]any `json:"excludeCredentials"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	fa.userHandle, _ = base64.RawURLEncoding.DecodeString(begin.Options.PublicKey.User.ID)
	if len(fa.userHandle) != 32 {
		t.Fatalf("user handle len = %d", len(fa.userHandle))
	}
	rr = do(srv, jsonReq("/account/passkeys/finish", map[string]any{
		"csrf_token": "csrf-1", "ceremony": begin.Ceremony, "name": name,
		"credential": fa.attest(t, begin.Options.PublicKey.Challenge),
	}, sc, csrfCookie()))
	if rr.Code != http.StatusCreated {
		t.Fatalf("finish = %d: %s", rr.Code, rr.Body.String())
	}
	return decodeJSON(t, rr)["id"].(string)
}

type loginBegin struct {
	Ceremony string `json:"ceremony"`
	Options  struct {
		PublicKey struct {
			Challenge        string           `json:"challenge"`
			AllowCredentials []map[string]any `json:"allowCredentials"`
		} `json:"publicKey"`
	} `json:"options"`
}

func beginPasskeyLogin(t *testing.T, srv *Server, username string) loginBegin {
	t.Helper()
	rr := do(srv, jsonReq("/login/passkey/begin", map[string]string{"csrf_token": "csrf-1", "username": username}, csrfCookie()))
	if rr.Code != http.StatusOK {
		t.Fatalf("login begin = %d: %s", rr.Code, rr.Body.String())
	}
	var lb loginBegin
	if err := json.Unmarshal(rr.Body.Bytes(), &lb); err != nil {
		t.Fatal(err)
	}
	return lb
}

func finishPasskeyLogin(t *testing.T, srv *Server, lb loginBegin, fa *fakeAuthenticator, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"csrf_token": "csrf-1", "ceremony": lb.Ceremony, "credential": fa.assert(t, lb.Options.PublicKey.Challenge)}
	for k, v := range extra {
		body[k] = v
	}
	return do(srv, jsonReq("/login/passkey/finish", body, csrfCookie()))
}

func sessionAMR(t *testing.T, srv *Server, rr *httptest.ResponseRecorder) string {
	t.Helper()
	sid := sessionCookie(rr)
	if sid == "" {
		t.Fatalf("no session cookie (%d): %s", rr.Code, rr.Body.String())
	}
	sess, err := srv.db.GetSession(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	return sess.AMR
}

// --- Scenarios 21, 22: local user registers and authenticates ---

func TestPasskeyRegisterAndDiscoverableLoginSkipsTOTPWithUV(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "root", "pw", true) // an admin exists, so /login renders instead of /setup
	alice := createUser(t, srv, "alice", "pw", false)
	enableMFA(t, srv, alice.ID, "JBSWY3DPEHPK3PXP") // TOTP enrolled, but a UV passkey is already MFA
	fa := newFakeAuthenticator(t, true)
	id := registerPasskey(t, srv, alice, fa, "MacBook Touch ID")

	rows, _ := srv.db.ListWebAuthnCredentials(context.Background(), alice.ID)
	if len(rows) != 1 || rows[0].ID != id || rows[0].Name != "MacBook Touch ID" || strings.Contains(rows[0].Credential, "\"d\"") {
		t.Fatalf("stored = %+v", rows)
	}

	// Usernameless (discoverable) login.
	lb := beginPasskeyLogin(t, srv, "")
	if len(lb.Options.PublicKey.AllowCredentials) != 0 {
		t.Errorf("discoverable login should not list credentials")
	}
	rr := finishPasskeyLogin(t, srv, lb, fa, map[string]any{"next": "/account/devices"})
	if rr.Code != http.StatusOK || decodeJSON(t, rr)["redirect"] != "/account/devices" {
		t.Fatalf("finish = %d: %s", rr.Code, rr.Body.String())
	}
	if amr := sessionAMR(t, srv, rr); amr != amrPasskeyUV {
		t.Errorf("amr = %q, want %q", amr, amrPasskeyUV)
	}
	if cookieFrom(rr, "omni_mfa") != "" {
		t.Error("UV passkey must not trigger the TOTP step")
	}
	// The credential's last-used time and counter were recorded.
	rows, _ = srv.db.ListWebAuthnCredentials(context.Background(), alice.ID)
	if rows[0].LastUsedAt.IsZero() || !strings.Contains(rows[0].Credential, `"signCount":1`) {
		t.Errorf("credential not updated: %+v", rows[0])
	}
	// The passkey pages render.
	req := httptest.NewRequest(http.MethodGet, "/account/passkeys", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sessionCookie(rr)})
	if p := do(srv, req); p.Code != 200 || !strings.Contains(p.Body.String(), "MacBook Touch ID") {
		t.Errorf("passkeys page: %d", p.Code)
	}
	if p := do(srv, httptest.NewRequest(http.MethodGet, "/static/webauthn.js", nil)); p.Code != 200 || !strings.Contains(p.Header().Get("Content-Type"), "javascript") {
		t.Errorf("static js: %d %s", p.Code, p.Header().Get("Content-Type"))
	}
	if p := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil)); !strings.Contains(p.Body.String(), "passkey-login") {
		t.Error("login page lacks the passkey button")
	}
}

func TestPasskeyWithoutUVFallsThroughToTOTP(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	secret := "JBSWY3DPEHPK3PXP"
	enableMFA(t, srv, alice.ID, secret)
	fa := newFakeAuthenticator(t, false) // e.g. a security key touched without PIN
	registerPasskey(t, srv, alice, fa, "YubiKey")

	rr := finishPasskeyLogin(t, srv, beginPasskeyLogin(t, srv, "alice"), fa, nil)
	if rr.Code != http.StatusOK || decodeJSON(t, rr)["redirect"] != "/login/mfa" {
		t.Fatalf("finish = %d: %s", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) != "" {
		t.Fatal("session issued before TOTP")
	}
	mfaCookie := cookieFrom(rr, "omni_mfa")
	if mfaCookie == "" {
		t.Fatal("no MFA challenge cookie")
	}
	code, _ := auth.TOTPCode(secret, time.Now())
	req := postForm("/login/mfa", url.Values{"csrf_token": {"csrf-1"}, "code": {code}}, "csrf-1")
	req.AddCookie(&http.Cookie{Name: "omni_mfa", Value: mfaCookie})
	rr = do(srv, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("mfa = %d: %s", rr.Code, rr.Body.String())
	}
	if amr := sessionAMR(t, srv, rr); amr != "webauthn user otp mfa" {
		t.Errorf("amr = %q", amr)
	}
}

func TestPasskeyUsernameFirstAndNoEnumeration(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	fa := newFakeAuthenticator(t, true)
	id := registerPasskey(t, srv, alice, fa, "key")

	lb := beginPasskeyLogin(t, srv, "alice")
	if len(lb.Options.PublicKey.AllowCredentials) != 1 || lb.Options.PublicKey.AllowCredentials[0]["id"] != id {
		t.Errorf("allowCredentials = %v", lb.Options.PublicKey.AllowCredentials)
	}
	// Unknown user / user without passkeys: a discoverable challenge, same shape.
	for _, name := range []string{"nobody", "bob"} {
		createUser(t, srv, "bob", "pw", false)
		lb := beginPasskeyLogin(t, srv, name)
		if len(lb.Options.PublicKey.AllowCredentials) != 0 || lb.Ceremony == "" {
			t.Errorf("%s: begin leaks account state: %+v", name, lb.Options.PublicKey)
		}
		break
	}
	// Username-first with the right credential logs in.
	fa.userHandle = nil // non-discoverable style: no user handle returned
	rr := finishPasskeyLogin(t, srv, lb, fa, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("finish = %d: %s", rr.Code, rr.Body.String())
	}
	if sessionAMR(t, srv, rr) != amrPasskeyUV {
		t.Error("wrong amr")
	}
}

// --- Scenarios 23, 24: LDAP-backed user ---

func TestPasskeyWorksForLDAPBackedUser(t *testing.T) {
	srv := testServer(t)
	now := time.Now().UTC()
	ldapUser := &model.User{ID: "ldap-1", Username: "carol", Email: "carol@example.com", AuthSource: "ldap",
		ExternalID: "uid=carol,ou=people,dc=example,dc=com", CreatedAt: now, UpdatedAt: now}
	if err := srv.db.CreateUser(context.Background(), ldapUser); err != nil {
		t.Fatal(err)
	}
	fa := newFakeAuthenticator(t, true)
	registerPasskey(t, srv, ldapUser, fa, "phone")
	rr := finishPasskeyLogin(t, srv, beginPasskeyLogin(t, srv, ""), fa, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ldap passkey login = %d: %s", rr.Code, rr.Body.String())
	}
	sid := sessionCookie(rr)
	sess, _ := srv.db.GetSession(context.Background(), sid)
	if sess.UserID != "ldap-1" {
		t.Errorf("session user = %s", sess.UserID)
	}
}

// --- Scenario 25 and abuse cases ---

func TestPasskeyRemovedReplayedAndClonedAreRejected(t *testing.T) {
	srv := testServer(t)
	alice := createUser(t, srv, "alice", "pw", false)
	fa := newFakeAuthenticator(t, true)
	id := registerPasskey(t, srv, alice, fa, "key")

	// Replaying a ceremony: the second answer to the same challenge fails.
	lb := beginPasskeyLogin(t, srv, "")
	if rr := finishPasskeyLogin(t, srv, lb, fa, nil); rr.Code != http.StatusOK {
		t.Fatalf("first login = %d", rr.Code)
	}
	if rr := finishPasskeyLogin(t, srv, lb, fa, nil); rr.Code != http.StatusBadRequest {
		t.Errorf("replayed ceremony accepted: %d", rr.Code)
	}
	// Wrong key for the credential id.
	impostor := newFakeAuthenticator(t, true)
	impostor.credID, impostor.userHandle = fa.credID, fa.userHandle
	if rr := finishPasskeyLogin(t, srv, beginPasskeyLogin(t, srv, ""), impostor, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("forged signature accepted: %d", rr.Code)
	}
	// Cloned authenticator: sign counter goes backwards.
	fa.counter = 0
	if rr := finishPasskeyLogin(t, srv, beginPasskeyLogin(t, srv, ""), fa, nil); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "counter") {
		t.Errorf("counter regression accepted: %d %s", rr.Code, rr.Body.String())
	}
	fa.counter = 10

	// Removed credential no longer works (scenario 25).
	sid := startSession(t, srv, alice.ID)
	rr := do(srv, sessionReq(sid, "/account/passkeys/"+id+"/delete", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Passkey removed") {
		t.Fatalf("delete = %d", rr.Code)
	}
	if rr := finishPasskeyLogin(t, srv, beginPasskeyLogin(t, srv, ""), fa, nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("removed passkey still logs in: %d", rr.Code)
	}
	// CSRF is enforced on the JSON endpoints.
	req := jsonReq("/login/passkey/begin", map[string]string{"csrf_token": "wrong"}, csrfCookie())
	if rr := do(srv, req); rr.Code != http.StatusForbidden {
		t.Errorf("csrf bypass: %d", rr.Code)
	}
}

func TestAdminCanResetPasskeys(t *testing.T) {
	srv := testServer(t)
	admin := createUser(t, srv, "root", "pw", true)
	alice := createUser(t, srv, "alice", "pw", false)
	registerPasskey(t, srv, alice, newFakeAuthenticator(t, true), "a")
	registerPasskey(t, srv, alice, newFakeAuthenticator(t, true), "b")
	sid := startSession(t, srv, admin.ID)
	req := httptest.NewRequest(http.MethodGet, "/admin/users/"+alice.ID, nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, req); !strings.Contains(rr.Body.String(), "Remove passkeys (2)") {
		t.Error("admin page lacks passkey reset")
	}
	if rr := do(srv, sessionReq(sid, "/admin/users/"+alice.ID+"/passkeys/reset", nil)); rr.Code != http.StatusSeeOther {
		t.Fatalf("reset = %d", rr.Code)
	}
	if n, _ := srv.db.CountWebAuthnCredentials(context.Background(), alice.ID); n != 0 {
		t.Errorf("passkeys left = %d", n)
	}
}

func TestPasskeysUnavailableWhenPublicURLIsAnIP(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.Config{}
	cfg.Server.PublicURL = "http://192.168.1.10:8080"
	cfg.Server.AllowInsecureHTTP = true
	cfg.Security.Issuer = cfg.Server.PublicURL
	cfg.Security.TokenTTL = 15 * time.Minute
	cfg.Security.RefreshTokenTTL = time.Hour
	cfg.Security.SessionLifetime = time.Hour
	cfg.Security.PasswordMinLength = 12
	srv, err := NewServer(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	createUser(t, srv, "root", "pw", true)
	if rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil)); strings.Contains(rr.Body.String(), "passkey-login") {
		t.Error("passkey button shown although the RP id is an IP address")
	}
	rr := do(srv, jsonReq("/login/passkey/begin", map[string]string{"csrf_token": "csrf-1"}, csrfCookie()))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("begin = %d", rr.Code)
	}
}
