package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// createClientFull registers a client with the full hosted-login metadata.
func createClientFull(t *testing.T, srv *Server, c *model.Client) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	c.CreatedAt, c.UpdatedAt = now, now
	if err := srv.db.CreateClient(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}
}

// authorizeReq builds an unauthenticated GET /oauth2/authorize request.
func authorizeReq(scope, challenge string) *http.Request {
	return httptest.NewRequest(http.MethodGet, authorizeURL(scope, challenge), nil)
}

// reqIDFromLogin extracts the parked request id from a /login?req=... redirect.
func reqIDFromLogin(t *testing.T, rr *httptest.ResponseRecorder, wantPrefix string) string {
	t.Helper()
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, wantPrefix) {
		t.Fatalf("location = %q, want prefix %q (body: %s)", loc, wantPrefix, rr.Body.String())
	}
	u, _ := url.Parse(loc)
	return u.Query().Get("req")
}

func TestUnauthenticatedAuthorizeParksAndLoginResumes(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "pw", true) // admin so /login isn't gated to /setup
	createClient(t, srv, "jellyfin", "topsecret", false,
		[]string{"https://jelly.example.com/cb"},
		[]string{"openid", "email", "profile"})

	// 1) Authorize with no session parks the request and bounces to /login.
	rr := do(srv, authorizeReq("openid email", pkceChallenge))
	reqID := reqIDFromLogin(t, rr, "/login?req=")
	if reqID == "" {
		t.Fatal("no req id in login redirect")
	}

	// The parked request preserved the original parameters.
	parked, err := srv.db.GetAuthRequest(context.Background(), reqID)
	if err != nil {
		t.Fatalf("parked request not stored: %v", err)
	}
	if parked.State != "st-123" || parked.Nonce != "n-xyz" || parked.CodeChallenge != pkceChallenge {
		t.Errorf("parked request lost params: %+v", parked)
	}

	// 2) The login page names the requesting application.
	formRR := do(srv, httptest.NewRequest(http.MethodGet, "/login?req="+reqID, nil))
	if !strings.Contains(formRR.Body.String(), "continue to jellyfin") {
		t.Errorf("login page missing app name; body: %s", formRR.Body.String())
	}

	// 3) Login resumes the flow and redirects back with code + state.
	form := url.Values{"username": {"alice"}, "password": {"pw"}, "csrf_token": {"tok"}, "req": {reqID}}
	loginRR := do(srv, postForm("/login", form, "tok"))
	if loginRR.Code != http.StatusSeeOther {
		t.Fatalf("login code = %d, want 303 (body: %s)", loginRR.Code, loginRR.Body.String())
	}
	loc, _ := url.Parse(loginRR.Header().Get("Location"))
	if loc.Host != "jelly.example.com" {
		t.Fatalf("redirect host = %q, want jelly.example.com", loc.Host)
	}
	if loc.Query().Get("code") == "" {
		t.Error("resumed login did not return a code")
	}
	if loc.Query().Get("state") != "st-123" {
		t.Errorf("state = %q, want st-123", loc.Query().Get("state"))
	}

	// The parked request is single-use: consumed after the code is issued.
	if _, err := srv.db.GetAuthRequest(context.Background(), reqID); err == nil {
		t.Error("auth request should be deleted after issuing a code")
	}
}

func TestExistingSessionSkipsLogin(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	sid := startSession(t, srv, user.ID)

	req := authorizeReq("openid", pkceChallenge)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Host != "jelly.example.com" || loc.Query().Get("code") == "" {
		t.Fatalf("authenticated authorize should issue code directly; loc=%q", rr.Header().Get("Location"))
	}
}

func TestConsentRequiredFlow(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClientFull(t, srv, &model.Client{
		ClientID: "thirdparty", Name: "Third Party App", DisplayName: "Third Party App",
		RedirectURIs:  []string{"https://jelly.example.com/cb"},
		AllowedScopes: []string{"openid", "email"}, Type: model.ClientTypeConfidential,
		ClientSecretHash: "x", SkipConsent: false,
	})
	sid := startSession(t, srv, user.ID)

	// jellyfin client_id is hardcoded in authorizeURL; build a custom URL here.
	v := url.Values{
		"response_type": {"code"}, "client_id": {"thirdparty"},
		"redirect_uri": {"https://jelly.example.com/cb"}, "scope": {"openid email"},
		"state": {"st-1"}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+v.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, req)
	reqID := reqIDFromLogin(t, rr, "/consent?req=")

	// Consent page shows scopes and the app.
	cReq := httptest.NewRequest(http.MethodGet, "/consent?req="+reqID, nil)
	cReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	cRR := do(srv, cReq)
	if !strings.Contains(cRR.Body.String(), "Third Party App") {
		t.Errorf("consent page missing app name; body: %s", cRR.Body.String())
	}

	// Allow -> code issued.
	allow := postForm("/consent", url.Values{"csrf_token": {"tok"}, "req": {reqID}, "action": {"allow"}}, "tok")
	allow.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	aRR := do(srv, allow)
	loc, _ := url.Parse(aRR.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("consent allow did not issue code; loc=%q", aRR.Header().Get("Location"))
	}
}

func TestConsentCancelReturnsAccessDenied(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClientFull(t, srv, &model.Client{
		ClientID: "thirdparty", Name: "TP", RedirectURIs: []string{"https://jelly.example.com/cb"},
		AllowedScopes: []string{"openid"}, Type: model.ClientTypeConfidential,
		ClientSecretHash: "x", SkipConsent: false,
	})
	sid := startSession(t, srv, user.ID)

	now := time.Now().UTC()
	parked := &model.AuthRequest{
		ID: "req-cancel", ClientID: "thirdparty", RedirectURI: "https://jelly.example.com/cb",
		ResponseType: "code", Scope: "openid", State: "st-9",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := srv.db.CreateAuthRequest(context.Background(), parked); err != nil {
		t.Fatal(err)
	}

	cancel := postForm("/consent", url.Values{"csrf_token": {"tok"}, "req": {"req-cancel"}, "action": {"cancel"}}, "tok")
	cancel.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, cancel)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("cancel error = %q, want access_denied", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "st-9" {
		t.Errorf("cancel state = %q, want st-9", loc.Query().Get("state"))
	}
}

func TestLoginRateLimited(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "pw", false)

	var last int
	for i := 0; i < loginMaxAttempts+1; i++ {
		form := url.Values{"username": {"alice"}, "password": {"wrong"}, "csrf_token": {"tok"}}
		last = do(srv, postForm("/login", form, "tok")).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d failed attempts, code = %d, want 429", loginMaxAttempts+1, last)
	}
}

func TestExpiredOrUnknownAuthRequestShowsError(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "alice", "pw", true) // admin so /login isn't gated to /setup
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login?req=does-not-exist", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for unknown req", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "expired") {
		t.Errorf("error page should mention expiry; body: %s", rr.Body.String())
	}
}

func TestRPInitiatedLogout(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClientFull(t, srv, &model.Client{
		ClientID: "jellyfin", Name: "Jellyfin", ClientSecretHash: auth.HashToken("topsecret"),
		RedirectURIs:           []string{"https://jelly.example.com/cb"},
		AllowedScopes:          []string{"openid", "email", "offline_access"},
		PostLogoutRedirectURIs: []string{"https://jelly.example.com/bye"},
		Type:                   model.ClientTypeConfidential, SkipConsent: true,
	})
	sid := startSession(t, srv, user.ID)

	// Run a full flow to obtain an id_token + refresh token.
	authReq := authorizeReq("openid email offline_access", pkceChallenge)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	code := loc.Query().Get("code")
	tokRR := do(srv, tokenPost(url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://jelly.example.com/cb"}, "client_id": {"jellyfin"},
		"client_secret": {"topsecret"}, "code_verifier": {pkceVerifier},
	}))
	var tok tokenResponse
	if err := json.Unmarshal(tokRR.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}

	// RP-initiated logout with a valid post_logout_redirect_uri + state.
	logoutURL := "/logout?" + url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {"https://jelly.example.com/bye"},
		"state":                    {"bye-state"},
	}.Encode()
	lReq := httptest.NewRequest(http.MethodGet, logoutURL, nil)
	lReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	lRR := do(srv, lReq)
	if lRR.Code != http.StatusSeeOther {
		t.Fatalf("logout code = %d, want 303 (body: %s)", lRR.Code, lRR.Body.String())
	}
	dest, _ := url.Parse(lRR.Header().Get("Location"))
	if dest.Host != "jelly.example.com" || dest.Path != "/bye" {
		t.Errorf("logout redirect = %q, want https://jelly.example.com/bye", lRR.Header().Get("Location"))
	}
	if dest.Query().Get("state") != "bye-state" {
		t.Errorf("logout state = %q, want bye-state", dest.Query().Get("state"))
	}

	// Session destroyed.
	if _, err := srv.db.GetSession(context.Background(), sid); err == nil {
		t.Error("session should be destroyed after logout")
	}
	// Refresh token for this user+client revoked.
	rt, err := srv.db.GetRefreshTokenByHash(context.Background(), auth.HashToken(tok.RefreshToken))
	if err != nil {
		t.Fatalf("refresh token lookup: %v", err)
	}
	if !rt.Revoked {
		t.Error("refresh token should be revoked after RP-initiated logout")
	}
}

func TestLogoutRejectsUnregisteredPostLogout(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClientFull(t, srv, &model.Client{
		ClientID: "jellyfin", Name: "Jellyfin", ClientSecretHash: auth.HashToken("topsecret"),
		RedirectURIs:  []string{"https://jelly.example.com/cb"},
		AllowedScopes: []string{"openid"}, Type: model.ClientTypeConfidential, SkipConsent: true,
	})
	sid := startSession(t, srv, user.ID)
	authReq := authorizeReq("openid", pkceChallenge)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	tokRR := do(srv, tokenPost(url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://jelly.example.com/cb"}, "client_id": {"jellyfin"},
		"client_secret": {"topsecret"}, "code_verifier": {pkceVerifier},
	}))
	var tok tokenResponse
	_ = json.Unmarshal(tokRR.Body.Bytes(), &tok)

	// Unregistered post_logout_redirect_uri must NOT redirect (no open redirect).
	logoutURL := "/logout?" + url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {"https://evil.example.com/bye"},
	}.Encode()
	rr := do(srv, httptest.NewRequest(http.MethodGet, logoutURL, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 signed-out page", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "signed out") {
		t.Errorf("expected signed-out page; body: %s", rr.Body.String())
	}
}

func TestBrandingDrivesLoginAndLogoRoute(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)

	b := &model.Branding{ProductName: "Acme SSO", AccentColor: "#abcdef"}
	if err := srv.db.UpdateBranding(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	srv.branding.Reload(context.Background())

	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil))
	if !strings.Contains(rr.Body.String(), "Acme SSO") {
		t.Errorf("login page missing branded product name; body: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "#abcdef") {
		t.Errorf("login page missing branded accent color")
	}

	// Logo route: 404 with no logo, serves bytes once set.
	if do(srv, httptest.NewRequest(http.MethodGet, "/branding/logo", nil)).Code != http.StatusNotFound {
		t.Error("expected 404 for missing logo")
	}
	png := []byte("\x89PNG\r\n\x1a\nfakepng")
	if err := srv.db.SetBrandingLogo(context.Background(), png, "image/png"); err != nil {
		t.Fatal(err)
	}
	logoRR := do(srv, httptest.NewRequest(http.MethodGet, "/branding/logo", nil))
	if logoRR.Code != http.StatusOK || logoRR.Header().Get("Content-Type") != "image/png" {
		t.Errorf("logo route: code=%d ct=%q", logoRR.Code, logoRR.Header().Get("Content-Type"))
	}
}

func TestSessionRotationOnLogin(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	// A pre-existing (potentially fixated) session.
	oldSID := startSession(t, srv, user.ID)

	form := url.Values{"username": {"alice"}, "password": {"pw"}, "csrf_token": {"tok"}}
	req := postForm("/login", form, "tok")
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: oldSID})
	rr := do(srv, req)

	newSID := sessionCookie(rr)
	if newSID == "" || newSID == oldSID {
		t.Fatalf("session id did not rotate: old=%q new=%q", oldSID, newSID)
	}
	if _, err := srv.db.GetSession(context.Background(), oldSID); err == nil {
		t.Error("old session should be deleted after rotation")
	}
}
