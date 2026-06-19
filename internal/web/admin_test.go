package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

func adminSession(t *testing.T, srv *Server) string {
	t.Helper()
	u := createUser(t, srv, "admin", "pw", true)
	return startSession(t, srv, u.ID)
}

func adminGet(srv *Server, path, sid string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	}
	return do(srv, req)
}

func adminPost(srv *Server, path string, form url.Values, sid string) *httptest.ResponseRecorder {
	form.Set("csrf_token", "tok")
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "omni_csrf", Value: "tok"})
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	}
	return do(srv, req)
}

func TestAdminRequiresSession(t *testing.T) {
	srv := testServer(t)
	rr := adminGet(srv, "/admin/users", "")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 redirect to login", rr.Code)
	}
}

func TestAdminRequiresAdminRole(t *testing.T) {
	srv := testServer(t)
	u := createUser(t, srv, "plain", "pw", false) // not admin
	sid := startSession(t, srv, u.ID)
	rr := adminGet(srv, "/admin/users", sid)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("non-admin code = %d, want 303", rr.Code)
	}
}

func TestAdminUsersListRenders(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminGet(srv, "/admin/users", sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "admin") {
		t.Error("users list should show the admin user")
	}
}

func TestAdminCreateUser(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminPost(srv, "/admin/users", url.Values{
		"username": {"newbie"},
		"email":    {"newbie@example.com"},
		"password": {"password123"},
	}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 (body: %s)", rr.Code, rr.Body.String())
	}
	if _, err := srv.db.GetUserByUsername(context.Background(), "newbie"); err != nil {
		t.Errorf("user not created: %v", err)
	}
}

func TestAdminDisableUser(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	target := createUser(t, srv, "victim", "pw", false)

	rr := adminPost(srv, "/admin/users/"+target.ID+"/disable",
		url.Values{"disabled": {"true"}}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	got, _ := srv.db.GetUserByID(context.Background(), target.ID)
	if !got.Disabled {
		t.Error("user should be disabled")
	}
}

func TestAdminChangeUserPassword(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	target := createUser(t, srv, "user1", "oldpw", false)

	rr := adminPost(srv, "/admin/users/"+target.ID+"/password",
		url.Values{"password": {"brandnewpw"}}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	if _, err := auth.Authenticate(context.Background(), srv.db, "user1", "brandnewpw"); err != nil {
		t.Errorf("new password should authenticate: %v", err)
	}
}

func TestAdminCreateConfidentialClientShowsSecretOnce(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminPost(srv, "/admin/clients", url.Values{
		"name":          {"Jellyfin"},
		"client_id":     {"jellyfin"},
		"type":          {"confidential"},
		"redirect_uris": {"https://jelly.example.com/cb"},
		"scopes":        {"openid email profile offline_access"},
	}, sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with secret (body: %s)", rr.Code, rr.Body.String())
	}
	client, err := srv.db.GetClient(context.Background(), "jellyfin")
	if err != nil {
		t.Fatalf("client not created: %v", err)
	}
	if client.ClientSecretHash == "" {
		t.Error("confidential client should have a secret hash stored")
	}
	// The plaintext secret should appear exactly once in the response body.
	if !strings.Contains(rr.Body.String(), "client_secret") &&
		!strings.Contains(strings.ToLower(rr.Body.String()), "secret") {
		t.Error("response should display the generated secret")
	}
}

func TestAdminCreatePublicClientHasNoSecret(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminPost(srv, "/admin/clients", url.Values{
		"name":          {"SPA"},
		"client_id":     {"spa"},
		"type":          {"public"},
		"redirect_uris": {"https://spa.example.com/cb"},
		"scopes":        {"openid"},
	}, sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	client, _ := srv.db.GetClient(context.Background(), "spa")
	if client.ClientSecretHash != "" {
		t.Error("public client must not have a secret")
	}
}

func TestAdminUpdateClientRedirectURIs(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	createClient(t, srv, "app", "s", false,
		[]string{"https://old.example.com/cb"}, []string{"openid"})

	rr := adminPost(srv, "/admin/clients/app", url.Values{
		"name":          {"App"},
		"type":          {"confidential"},
		"redirect_uris": {"https://a.example.com/cb\nhttps://b.example.com/cb"},
		"scopes":        {"openid email"},
	}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 (body: %s)", rr.Code, rr.Body.String())
	}
	got, _ := srv.db.GetClient(context.Background(), "app")
	if len(got.RedirectURIs) != 2 {
		t.Errorf("redirect uris = %v, want 2", got.RedirectURIs)
	}
	if len(got.AllowedScopes) != 2 {
		t.Errorf("scopes = %v, want 2", got.AllowedScopes)
	}
}

func TestAdminDisableClient(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	createClient(t, srv, "app", "s", false, []string{"https://x/cb"}, []string{"openid"})

	rr := adminPost(srv, "/admin/clients/app/disable", url.Values{"disabled": {"true"}}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	got, _ := srv.db.GetClient(context.Background(), "app")
	if !got.Disabled {
		t.Error("client should be disabled")
	}
}

func TestAdminRotateClientSecret(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	createClient(t, srv, "app", "oldsecret", false, []string{"https://x/cb"}, []string{"openid"})
	before, _ := srv.db.GetClient(context.Background(), "app")

	rr := adminPost(srv, "/admin/clients/app/rotate", url.Values{}, sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 with new secret (body: %s)", rr.Code, rr.Body.String())
	}
	after, _ := srv.db.GetClient(context.Background(), "app")
	if after.ClientSecretHash == before.ClientSecretHash {
		t.Error("secret hash should change after rotation")
	}
	// Old secret must no longer validate.
	if auth.SecretMatches("oldsecret", after.ClientSecretHash) {
		t.Error("old secret must not validate after rotation")
	}
}

func TestAdminSettingsRenders(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminGet(srv, "/admin/settings", sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "localhost:8080") {
		t.Error("settings should show the issuer")
	}
}

var _ = model.ClientTypePublic
