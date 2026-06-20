package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// rfc6238Secret is a fixed base32 TOTP secret for deterministic MFA tests.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func cookieFrom(rr *httptest.ResponseRecorder, name string) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// --- Account lockout ---

func TestAccountLockoutAfterFailedAttempts(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "correct-horse-1", true)

	// Five wrong passwords, each from a distinct IP so the per-IP rate limiter
	// does not mask the per-account lockout.
	for i := 0; i < srv.cfg.Security.MaxFailedLogins; i++ {
		req := postForm("/login", url.Values{
			"username": {"alice"}, "password": {"wrong"}, "csrf_token": {"tok"},
		}, "tok")
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:1", i+1)
		if rr := do(srv, req); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d code = %d, want 401", i+1, rr.Code)
		}
	}

	// Correct password from a fresh IP is now refused: the account is locked.
	req := postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok")
	req.RemoteAddr = "10.0.99.99:1"
	rr := do(srv, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login code = %d, want 429 (body: %s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "locked") {
		t.Errorf("expected lockout message; body: %s", rr.Body.String())
	}
	if sessionCookie(rr) != "" {
		t.Error("must not issue a session while locked")
	}
}

func TestAdminUnlockRestoresLogin(t *testing.T) {
	srv := testServer(t)
	admin := adminSession(t, srv)
	user := createUser(t, srv, "bob", "correct-horse-1", false)

	// Lock the account directly.
	_, err := srv.db.RecordFailedLogin(context.Background(), user.ID,
		srv.cfg.Security.MaxFailedLogins, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < srv.cfg.Security.MaxFailedLogins; i++ {
		_, _ = srv.db.RecordFailedLogin(context.Background(), user.ID,
			srv.cfg.Security.MaxFailedLogins, time.Now().Add(time.Hour))
	}

	rr := adminPost(srv, "/admin/users/"+user.ID+"/unlock", url.Values{}, admin)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("unlock code = %d, want 303", rr.Code)
	}
	got, _ := srv.db.GetUserByID(context.Background(), user.ID)
	if got.IsLocked(time.Now()) {
		t.Error("account should be unlocked")
	}
}

// --- MFA ---

func enableMFA(t *testing.T, srv *Server, userID, secret string) {
	t.Helper()
	enc, err := srv.enc.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.db.SetUserMFA(context.Background(), userID, true, enc); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRequiresSecondFactorThenSucceeds(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", true)
	enableMFA(t, srv, user.ID, rfc6238Secret)

	// Password step: no session yet, diverted to the MFA challenge.
	loginRR := do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok"))
	if loginRR.Code != http.StatusSeeOther || loginRR.Header().Get("Location") != "/login/mfa" {
		t.Fatalf("password step: code=%d loc=%q", loginRR.Code, loginRR.Header().Get("Location"))
	}
	if sessionCookie(loginRR) != "" {
		t.Fatal("session must not be issued before the second factor")
	}
	mfaCookie := cookieFrom(loginRR, mfaCookieName)
	if mfaCookie == "" {
		t.Fatal("no MFA challenge cookie set")
	}

	// MFA step: submit a valid TOTP code.
	code, _ := auth.TOTPCode(rfc6238Secret, time.Now().UTC())
	mfaReq := postForm("/login/mfa", url.Values{"code": {code}, "csrf_token": {"tok"}}, "tok")
	mfaReq.AddCookie(&http.Cookie{Name: mfaCookieName, Value: mfaCookie})
	mfaRR := do(srv, mfaReq)
	if mfaRR.Code != http.StatusSeeOther {
		t.Fatalf("mfa step code = %d, want 303 (body: %s)", mfaRR.Code, mfaRR.Body.String())
	}
	if sessionCookie(mfaRR) == "" {
		t.Error("expected a session after passing MFA")
	}
}

func TestMFARejectsWrongCode(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", true)
	enableMFA(t, srv, user.ID, rfc6238Secret)

	loginRR := do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok"))
	mfaCookie := cookieFrom(loginRR, mfaCookieName)

	mfaReq := postForm("/login/mfa", url.Values{"code": {"000000"}, "csrf_token": {"tok"}}, "tok")
	mfaReq.AddCookie(&http.Cookie{Name: mfaCookieName, Value: mfaCookie})
	rr := do(srv, mfaReq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code = %d, want 401", rr.Code)
	}
	if sessionCookie(rr) != "" {
		t.Error("must not issue session on wrong MFA code")
	}
}

func TestMFARecoveryCodeWorks(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", true)
	enableMFA(t, srv, user.ID, rfc6238Secret)

	plain, records := newRecoveryCodeSet(3)
	if err := srv.db.ReplaceRecoveryCodes(context.Background(), user.ID, records); err != nil {
		t.Fatal(err)
	}

	loginRR := do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok"))
	mfaCookie := cookieFrom(loginRR, mfaCookieName)

	mfaReq := postForm("/login/mfa", url.Values{"code": {plain[0]}, "csrf_token": {"tok"}}, "tok")
	mfaReq.AddCookie(&http.Cookie{Name: mfaCookieName, Value: mfaCookie})
	rr := do(srv, mfaReq)
	if rr.Code != http.StatusSeeOther || sessionCookie(rr) == "" {
		t.Fatalf("recovery login code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	// The recovery code is single-use.
	left, _ := srv.db.CountRecoveryCodes(context.Background(), user.ID)
	if left != 2 {
		t.Errorf("remaining recovery codes = %d, want 2", left)
	}
}

// --- Introspection + client_credentials ---

func TestClientCredentialsAndIntrospection(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "svc", "svc-secret", false,
		[]string{"https://svc.example.com/cb"}, []string{"openid", "email", "profile"})

	// client_credentials issues an access token (no id/refresh token).
	ccRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc"},
		"client_secret": {"svc-secret"},
		"scope":         {"email"},
	}))
	if ccRR.Code != http.StatusOK {
		t.Fatalf("client_credentials code = %d (body: %s)", ccRR.Code, ccRR.Body.String())
	}
	var tok tokenResponse
	_ = json.Unmarshal(ccRR.Body.Bytes(), &tok)
	if tok.AccessToken == "" || tok.RefreshToken != "" || tok.IDToken != "" {
		t.Fatalf("unexpected client_credentials tokens: %+v", tok)
	}

	// Introspection reports the token active.
	introRR := do(srv, func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
			strings.NewReader(url.Values{
				"token": {tok.AccessToken}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
			}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}())
	if introRR.Code != http.StatusOK {
		t.Fatalf("introspect code = %d", introRR.Code)
	}
	var info map[string]any
	_ = json.Unmarshal(introRR.Body.Bytes(), &info)
	if info["active"] != true {
		t.Errorf("introspection active = %v, want true (body: %s)", info["active"], introRR.Body.String())
	}
}

func TestClientCredentialsRejectsPublicClient(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "spa", "", true,
		[]string{"https://spa.example.com/cb"}, []string{"openid"})
	rr := do(srv, tokenPost(url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"spa"},
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("public client_credentials code = %d, want 401", rr.Code)
	}
}

func TestIntrospectionRequiresClientAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect",
		strings.NewReader("token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := do(srv, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated introspect code = %d, want 401", rr.Code)
	}
}

// --- prompt / max_age ---

func authorizeURLWith(extra url.Values) string {
	v := url.Values{
		"response_type": {"code"}, "client_id": {"jellyfin"},
		"redirect_uri": {"https://jelly.example.com/cb"}, "scope": {"openid"},
		"state": {"st"}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		v[k] = vs
	}
	return "/oauth2/authorize?" + v.Encode()
}

func TestPromptNoneWithoutSessionReturnsLoginRequired(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})

	rr := do(srv, httptest.NewRequest(http.MethodGet, authorizeURLWith(url.Values{"prompt": {"none"}}), nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", loc.Query().Get("error"))
	}
}

func TestMaxAgeZeroForcesReauth(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", false)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	sid := startSession(t, srv, user.ID)

	req := httptest.NewRequest(http.MethodGet, authorizeURLWith(url.Values{"max_age": {"0"}}), nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, req)
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?req=") {
		t.Errorf("max_age=0 should force re-auth; loc=%q", rr.Header().Get("Location"))
	}
}

// --- Self-service account ---

func TestAccountPasswordChangeRequiresCurrentAndRevokesOthers(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", false)
	sid := startSession(t, srv, user.ID)
	other := startSession(t, srv, user.ID)

	// Wrong current password is rejected.
	bad := postForm("/account/password", url.Values{
		"current_password": {"nope"}, "new_password": {"new-horse-battery-2"}, "csrf_token": {"tok"},
	}, "tok")
	bad.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, bad); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password code = %d, want 401", rr.Code)
	}

	// Correct change succeeds and revokes the *other* session.
	good := postForm("/account/password", url.Values{
		"current_password": {"correct-horse-1"}, "new_password": {"new-horse-battery-2"}, "csrf_token": {"tok"},
	}, "tok")
	good.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, good); rr.Code != http.StatusOK {
		t.Fatalf("password change code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	if _, err := srv.db.GetSession(context.Background(), other); err == nil {
		t.Error("other session should have been revoked")
	}
	if _, err := srv.db.GetSession(context.Background(), sid); err != nil {
		t.Error("current session should survive")
	}
}

func TestRevokeOtherSessions(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "correct-horse-1", false)
	sid := startSession(t, srv, user.ID)
	other := startSession(t, srv, user.ID)

	req := postForm("/account/sessions/revoke", url.Values{"csrf_token": {"tok"}}, "tok")
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	if rr := do(srv, req); rr.Code != http.StatusOK {
		t.Fatalf("revoke code = %d", rr.Code)
	}
	if _, err := srv.db.GetSession(context.Background(), other); err == nil {
		t.Error("other session should be gone")
	}
}

// --- Audit log ---

func TestAuditRecordsLoginEvents(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "correct-horse-1", true)

	do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"wrong"}, "csrf_token": {"tok"},
	}, "tok"))
	do(srv, postForm("/login", url.Values{
		"username": {"alice"}, "password": {"correct-horse-1"}, "csrf_token": {"tok"},
	}, "tok"))

	events, err := srv.db.ListAuditEvents(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var sawFail, sawSuccess bool
	for _, e := range events {
		if e.Event == evtLoginFailed {
			sawFail = true
		}
		if e.Event == evtLoginSuccess && e.Success {
			sawSuccess = true
		}
	}
	if !sawFail || !sawSuccess {
		t.Errorf("audit missing events: fail=%v success=%v", sawFail, sawSuccess)
	}
}

// --- Session idle timeout ---

func TestSessionIdleTimeoutExpires(t *testing.T) {
	srv := testServer(t)
	srv.sessions.SetIdleTimeout(time.Minute)
	user := createUser(t, srv, "alice", "correct-horse-1", false)

	// A session last seen well beyond the idle window.
	old := time.Now().UTC().Add(-2 * time.Hour)
	sess := &model.Session{
		ID: "idle-sess", UserID: user.ID, CSRFSecret: "x",
		CreatedAt: old, ExpiresAt: time.Now().UTC().Add(time.Hour), LastSeenAt: old,
	}
	if err := srv.db.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: "idle-sess"})
	rr := do(srv, req)
	// Idle session is rejected -> redirected to login.
	if rr.Code != http.StatusSeeOther || !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Errorf("idle session should be expired; code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}
