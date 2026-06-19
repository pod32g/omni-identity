package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/tokens"
)

// Finding 7: an expired access token must be rejected at /userinfo.
func TestUserinfoRejectsExpiredAccessToken(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)

	expIssuer := tokens.NewIssuer(srv.keys, srv.cfg.Security.Issuer, -time.Minute, -time.Minute)
	at, err := expIssuer.IssueAccessToken(user.ID, "jellyfin", "openid email")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	if rr := do(srv, req); rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 for expired access token", rr.Code)
	}
}

// Finding 8: an ID token must not be accepted as a Bearer token at /userinfo.
func TestUserinfoRejectsIDTokenAsBearer(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "bob", "pw", false)

	idTok, err := srv.issuer.IssueIDToken(user.ID, "jellyfin",
		tokens.Profile{Email: user.Email, PreferredUsername: user.Username}, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+idTok)
	if rr := do(srv, req); rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401 when an ID token is used as a bearer token", rr.Code)
	}
}

// Finding 10: an expired refresh token must be rejected at the token endpoint.
func TestRefreshExpiredTokenRejected(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "carol", "pw", false)
	createClient(t, srv, "jellyfin", "secret", false,
		[]string{"https://x/cb"}, []string{"openid", "offline_access"})

	now := time.Now().UTC()
	rt := &model.RefreshToken{
		ID:        uuid.NewString(),
		TokenHash: auth.HashToken("expiredtoken"),
		ClientID:  "jellyfin",
		UserID:    user.ID,
		Scope:     "openid offline_access",
		ExpiresAt: now.Add(-time.Hour), // expired
		CreatedAt: now.Add(-2 * time.Hour),
		AuthTime:  now.Add(-2 * time.Hour),
	}
	if err := srv.db.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatal(err)
	}

	rr := do(srv, tokenPost(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"expiredtoken"},
		"client_id":     {"jellyfin"},
		"client_secret": {"secret"},
	}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400 invalid_grant for expired refresh token", rr.Code)
	}
}

// Findings 3/6: the ID token auth_time must reflect the session login time, not
// the token issuance time.
func TestIDTokenAuthTimeMatchesSessionLogin(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "dave", "pw", false)
	createClient(t, srv, "jellyfin", "secret", false,
		[]string{"https://jelly.example.com/cb"},
		[]string{"openid", "email", "offline_access"})

	// A session that was created in the past.
	loginTime := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	sess := &model.Session{
		ID: uuid.NewString(), UserID: user.ID, CSRFSecret: "c",
		CreatedAt: loginTime, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := srv.db.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid email offline_access", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sess.ID})
	loc, _ := url.Parse(do(srv, authReq).Header().Get("Location"))
	code := loc.Query().Get("code")

	tokRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://jelly.example.com/cb"},
		"client_id":     {"jellyfin"},
		"client_secret": {"secret"},
		"code_verifier": {pkceVerifier},
	}))
	var tok tokenResponse
	_ = json.Unmarshal(tokRR.Body.Bytes(), &tok)

	vt, err := srv.issuer.Verify(tok.IDToken)
	if err != nil {
		t.Fatalf("verify id token: %v", err)
	}
	authTime, ok := vt.Claims["auth_time"].(float64)
	if !ok {
		t.Fatal("auth_time missing")
	}
	if int64(authTime) != loginTime.Unix() {
		t.Errorf("auth_time = %d, want session login time %d", int64(authTime), loginTime.Unix())
	}

	// And it must be preserved across a refresh.
	refRR := do(srv, tokenPost(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"jellyfin"},
		"client_secret": {"secret"},
	}))
	var tok2 tokenResponse
	_ = json.Unmarshal(refRR.Body.Bytes(), &tok2)
	vt2, err := srv.issuer.Verify(tok2.IDToken)
	if err != nil {
		t.Fatalf("verify refreshed id token: %v", err)
	}
	if at2, _ := vt2.Claims["auth_time"].(float64); int64(at2) != loginTime.Unix() {
		t.Errorf("refreshed auth_time = %d, want %d (preserved)", int64(at2), loginTime.Unix())
	}
}
