package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pod32g/omni-identity/internal/model"
)

// codeFlowTokens runs the authorization-code flow for user against the
// jellyfin test client and returns the decoded token response.
func codeFlowTokens(t *testing.T, srv *Server, user *model.User) map[string]any {
	t.Helper()
	authReq := httptest.NewRequest(http.MethodGet, authorizeURL("openid email profile", pkceChallenge), nil)
	authReq.AddCookie(&http.Cookie{Name: "omni_session", Value: startSession(t, srv, user.ID)})
	authRR := do(srv, authReq)
	if authRR.Code != http.StatusSeeOther {
		t.Fatalf("authorize = %d: %s", authRR.Code, authRR.Body.String())
	}
	loc, _ := url.Parse(authRR.Header().Get("Location"))
	rr := do(srv, tokenPost(url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://jelly.example.com/cb"}, "client_id": {"jellyfin"},
		"client_secret": {"topsecret"}, "code_verifier": {pkceVerifier},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rr.Code, rr.Body.String())
	}
	return decodeJSON(t, rr)
}

func userinfoClaims(t *testing.T, srv *Server, access string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rr := do(srv, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("userinfo = %d: %s", rr.Code, rr.Body.String())
	}
	return decodeJSON(t, rr)
}

// Administrators carry groups=["admins"] on the ID token, the access token,
// and userinfo; everyone else has no groups claim at all.
func TestGroupsClaimReflectsAdminMembership(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "topsecret", false, []string{"https://jelly.example.com/cb"}, []string{"openid", "email", "profile"})
	admin := createUser(t, srv, "alice", "pw", true)
	member := createUser(t, srv, "bob", "pw", false)

	tok := codeFlowTokens(t, srv, admin)
	for _, name := range []string{"id_token", "access_token"} {
		groups, _ := jwtClaims(t, tok[name].(string))["groups"].([]any)
		if len(groups) != 1 || groups[0] != "admins" {
			t.Errorf("admin %s groups = %v, want [admins]", name, groups)
		}
	}
	if groups, _ := userinfoClaims(t, srv, tok["access_token"].(string))["groups"].([]any); len(groups) != 1 || groups[0] != "admins" {
		t.Errorf("admin userinfo groups = %v", groups)
	}

	tok = codeFlowTokens(t, srv, member)
	for _, name := range []string{"id_token", "access_token"} {
		if v, ok := jwtClaims(t, tok[name].(string))["groups"]; ok {
			t.Errorf("non-admin %s carries groups = %v", name, v)
		}
	}
	if v, ok := userinfoClaims(t, srv, tok["access_token"].(string))["groups"]; ok {
		t.Errorf("non-admin userinfo carries groups = %v", v)
	}
}

func TestDiscoveryAdvertisesGroupsClaim(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var doc struct {
		ClaimsSupported []string `json:"claims_supported"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.ClaimsSupported {
		if c == "groups" {
			return
		}
	}
	t.Errorf("claims_supported = %v lacks groups", doc.ClaimsSupported)
}
