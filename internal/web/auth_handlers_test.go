package web

import (
	"context"
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

func do(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

func createUser(t *testing.T, srv *Server, username, password string, admin bool) *model.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	u := &model.User{
		ID:           uuid.NewString(),
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: hash,
		IsAdmin:      admin,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := srv.db.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func postForm(path string, form url.Values, csrf string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: "omni_csrf", Value: csrf})
	}
	return req
}

func sessionCookie(rr *httptest.ResponseRecorder) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "omni_session" && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// --- login ---

func TestGetLoginRedirectsToSetupWhenNoAdmin(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/setup" {
		t.Errorf("location = %q, want /setup", loc)
	}
}

func TestGetLoginRendersFormWhenAdminExists(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "csrf_token") {
		t.Error("login form missing csrf_token field")
	}
	if !strings.Contains(body, `name="username"`) {
		t.Error("login form missing username field")
	}
}

func TestPostLoginSuccessSetsSession(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)

	form := url.Values{"username": {"admin"}, "password": {"pw"}, "csrf_token": {"tok"}}
	rr := do(srv, postForm("/login", form, "tok"))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 (body: %s)", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) == "" {
		t.Error("expected a session cookie after successful login")
	}
}

func TestPostLoginWrongPasswordNoSession(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)

	form := url.Values{"username": {"admin"}, "password": {"nope"}, "csrf_token": {"tok"}}
	rr := do(srv, postForm("/login", form, "tok"))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
	if sessionCookie(rr) != "" {
		t.Error("must not set session cookie on failed login")
	}
}

func TestPostLoginMissingCSRFRejected(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)

	form := url.Values{"username": {"admin"}, "password": {"pw"}}
	rr := do(srv, postForm("/login", form, "")) // no csrf cookie
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rr.Code)
	}
}

// --- logout ---

func TestPostLogoutDestroysSession(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)
	loginRR := do(srv, postForm("/login",
		url.Values{"username": {"admin"}, "password": {"pw"}, "csrf_token": {"tok"}}, "tok"))
	sid := sessionCookie(loginRR)
	if sid == "" {
		t.Fatal("login did not set session")
	}

	logoutReq := postForm("/logout", url.Values{"csrf_token": {"tok2"}}, "tok2")
	logoutReq.AddCookie(&http.Cookie{Name: "omni_session", Value: sid})
	rr := do(srv, logoutReq)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}

	// Session must no longer resolve.
	if _, err := srv.db.GetSession(context.Background(), sid); err == nil {
		t.Error("session should be deleted after logout")
	}
}

// --- setup wizard ---

func TestGetSetupShowsFormWhenNoAdmin(t *testing.T) {
	srv := testServer(t)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `name="username"`) {
		t.Error("setup form missing username field")
	}
}

func TestGetSetupRedirectsWhenAdminExists(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Errorf("location = %q, want /login", loc)
	}
}

func TestPostSetupCreatesFirstAdmin(t *testing.T) {
	srv := testServer(t)
	form := url.Values{
		"username":   {"root"},
		"email":      {"root@example.com"},
		"password":   {"supersecret"},
		"csrf_token": {"tok"},
	}
	rr := do(srv, postForm("/setup", form, "tok"))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want 303 (body: %s)", rr.Code, rr.Body.String())
	}
	n, _ := srv.db.CountAdmins(context.Background())
	if n != 1 {
		t.Errorf("admin count = %d, want 1", n)
	}
	if sessionCookie(rr) == "" {
		t.Error("expected to be logged in after setup")
	}
}

func TestPostSetupBlockedWhenAdminExists(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "pw", true)
	form := url.Values{
		"username":   {"intruder"},
		"email":      {"x@example.com"},
		"password":   {"password"},
		"csrf_token": {"tok"},
	}
	rr := do(srv, postForm("/setup", form, "tok"))
	if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/admin" {
		t.Fatal("setup must not create a second admin")
	}
	n, _ := srv.db.CountAdmins(context.Background())
	if n != 1 {
		t.Errorf("admin count = %d, want 1 (setup should be blocked)", n)
	}
}
