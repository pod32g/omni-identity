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

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func createClient(t *testing.T, srv *Server, id, secret string, public bool, redirects, scopes []string) {
	t.Helper()
	typ := model.ClientTypeConfidential
	hash := auth.HashToken(secret)
	if public {
		typ = model.ClientTypePublic
		hash = ""
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := &model.Client{
		ClientID:         id,
		ClientSecretHash: hash,
		Name:             id,
		RedirectURIs:     redirects,
		AllowedScopes:    scopes,
		Type:             typ,
		SkipConsent:      true, // first-party test clients skip the consent screen
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := srv.db.CreateClient(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}
}

func startSession(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	now := time.Now().UTC()
	sess := &model.Session{
		ID:         uuid.NewString(),
		UserID:     userID,
		CSRFSecret: "csrf",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := srv.db.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID
}

func authorizeURL(scope, challenge string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {"jellyfin"},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"scope":         {scope},
		"state":         {"st-123"},
		"nonce":         {"n-xyz"},
	}
	if challenge != "" {
		v.Set("code_challenge", challenge)
		v.Set("code_challenge_method", "S256")
	}
	return "/oauth2/authorize?" + v.Encode()
}

func tokenPost(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "jellyfin", "topsecret", false,
		[]string{"https://jelly.example.com/cb"},
		[]string{"openid", "email", "profile", "offline_access"})
	sid := startSession(t, srv, user.ID)

	// 1) Authorize -> redirect with code.
	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid email profile offline_access", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	authRR := do(srv, authReq)
	if authRR.Code != http.StatusSeeOther {
		t.Fatalf("authorize code = %d, want 303 (body: %s)", authRR.Code, authRR.Body.String())
	}
	loc, _ := url.Parse(authRR.Header().Get("Location"))
	if loc.Query().Get("state") != "st-123" {
		t.Errorf("state = %q, want st-123", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("authorize did not return a code")
	}

	// 2) Token exchange.
	tokRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"client_id":     {"jellyfin"},
		"client_secret": {"topsecret"},
		"code_verifier": {pkceVerifier},
	}))
	if tokRR.Code != http.StatusOK {
		t.Fatalf("token code = %d, want 200 (body: %s)", tokRR.Code, tokRR.Body.String())
	}
	var tok tokenResponse
	if err := json.Unmarshal(tokRR.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tok.AccessToken == "" || tok.IDToken == "" || tok.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q", tok.TokenType)
	}

	// ID token must verify and carry the nonce + subject.
	idvt, err := srv.issuer.Verify(tok.IDToken)
	if err != nil {
		t.Fatalf("id token verify: %v", err)
	}
	if idvt.Subject != user.ID {
		t.Errorf("id token sub = %q, want %q", idvt.Subject, user.ID)
	}
	if idvt.Claims["nonce"] != "n-xyz" {
		t.Errorf("id token nonce = %v", idvt.Claims["nonce"])
	}

	// 3) Userinfo with the access token.
	uReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uRR := do(srv, uReq)
	if uRR.Code != http.StatusOK {
		t.Fatalf("userinfo code = %d (body: %s)", uRR.Code, uRR.Body.String())
	}
	var info map[string]any
	_ = json.Unmarshal(uRR.Body.Bytes(), &info)
	if info["sub"] != user.ID {
		t.Errorf("userinfo sub = %v", info["sub"])
	}
	if info["email"] != "alice@example.com" {
		t.Errorf("userinfo email = %v", info["email"])
	}
	if info["preferred_username"] != "alice" {
		t.Errorf("userinfo preferred_username = %v", info["preferred_username"])
	}

	// 4) Refresh -> rotated refresh token.
	refRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"jellyfin"},
		"client_secret": {"topsecret"},
	}))
	if refRR.Code != http.StatusOK {
		t.Fatalf("refresh code = %d (body: %s)", refRR.Code, refRR.Body.String())
	}
	var tok2 tokenResponse
	_ = json.Unmarshal(refRR.Body.Bytes(), &tok2)
	if tok2.AccessToken == "" || tok2.RefreshToken == "" {
		t.Fatal("refresh did not return new tokens")
	}
	if tok2.RefreshToken == tok.RefreshToken {
		t.Error("refresh token must rotate")
	}

	// 5) Reusing the old (now revoked) refresh token must fail.
	reuseRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"jellyfin"},
		"client_secret": {"topsecret"},
	}))
	if reuseRR.Code != http.StatusBadRequest {
		t.Errorf("reused refresh token code = %d, want 400", reuseRR.Code)
	}
	// Reuse detection should also revoke the rotated token's chain.
	chainRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok2.RefreshToken},
		"client_id":     {"jellyfin"},
		"client_secret": {"topsecret"},
	}))
	if chainRR.Code != http.StatusBadRequest {
		t.Errorf("chain token after reuse code = %d, want 400 (revoked)", chainRR.Code)
	}
}

func TestPublicClientPKCEFlow(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "bob", "pw", false)
	createClient(t, srv, "jellyfin", "", true,
		[]string{"https://jelly.example.com/cb"},
		[]string{"openid", "email"})
	sid := startSession(t, srv, user.ID)

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid email", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	authRR := do(srv, authReq)
	loc, _ := url.Parse(authRR.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code for public client (body: %s)", authRR.Body.String())
	}

	// No client_secret; PKCE proves possession.
	tokRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"client_id":     {"jellyfin"},
		"code_verifier": {pkceVerifier},
	}))
	if tokRR.Code != http.StatusOK {
		t.Fatalf("public client token code = %d (body: %s)", tokRR.Code, tokRR.Body.String())
	}
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "carol", "pw", false)
	createClient(t, srv, "jellyfin", "", true,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	sid := startSession(t, srv, user.ID)

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid", ""), nil) // no challenge
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	authRR := do(srv, authReq)
	loc, _ := url.Parse(authRR.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", loc.Query().Get("error"))
	}
}

func TestAuthorizeUnknownClientShowsErrorPage(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=ghost&redirect_uri=https://x/cb&scope=openid", nil)
	rr := do(srv, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rr.Code)
	}
}

func TestAuthorizeBadRedirectShowsErrorPage(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "s", false, []string{"https://jelly.example.com/cb"}, []string{"openid"})
	req := httptest.NewRequest(http.MethodGet,
		"/oauth2/authorize?response_type=code&client_id=jellyfin&redirect_uri=https://evil/cb&scope=openid", nil)
	rr := do(srv, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 for mismatched redirect_uri", rr.Code)
	}
}

func TestAuthorizeWithoutSessionRedirectsToLogin(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	req := httptest.NewRequest(http.MethodGet, authorizeURL("openid", pkceChallenge), nil)
	rr := do(srv, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login?req=") {
		t.Errorf("location = %q, want /login?req=...", rr.Header().Get("Location"))
	}
}

func TestAuthorizeInvalidScopeRedirectsError(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "dave", "pw", false)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"}) // email not allowed
	sid := startSession(t, srv, user.ID)

	req := httptest.NewRequest(http.MethodGet, authorizeURL("openid email", pkceChallenge), nil)
	req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", loc.Query().Get("error"))
	}
}

func TestTokenWrongClientSecretRejected(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "erin", "pw", false)
	createClient(t, srv, "jellyfin", "rightsecret", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	sid := startSession(t, srv, user.ID)

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	code := loc.Query().Get("code")

	rr := do(srv, tokenPost(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"client_id":     {"jellyfin"},
		"client_secret": {"wrongsecret"},
		"code_verifier": {pkceVerifier},
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 invalid_client", rr.Code)
	}
}

func TestTokenPKCEMismatchRejected(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "frank", "pw", false)
	createClient(t, srv, "jellyfin", "s", false,
		[]string{"https://jelly.example.com/cb"}, []string{"openid"})
	sid := startSession(t, srv, user.ID)

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	code := loc.Query().Get("code")

	rr := do(srv, tokenPost(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"client_id":     {"jellyfin"},
		"client_secret": {"s"},
		"code_verifier": {"wrong-verifier"},
	}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 invalid_grant for bad PKCE", rr.Code)
	}
}

func TestUserinfoRejectsInvalidToken(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := do(srv, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestUserinfoIgnoresQueryAndFormAccessTokens(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/userinfo?access_token=not-a-real-token", nil)
	rr := do(srv, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("query token code = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing bearer token") {
		t.Fatalf("query token should be ignored; body: %s", rr.Body.String())
	}

	form := url.Values{"access_token": {"not-a-real-token"}}
	req = httptest.NewRequest(http.MethodPost, "/userinfo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = do(srv, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("form token code = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing bearer token") {
		t.Fatalf("form token should be ignored; body: %s", rr.Body.String())
	}
}
