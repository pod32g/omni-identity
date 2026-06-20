package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/pod32g/omni-identity/internal/authn"
)

// fakeConn is an in-memory PasswordConnector for tests.
type fakeConn struct {
	id  authn.Identity
	ok  bool
	err error
}

func (fakeConn) ID() string { return "ldap" }
func (f fakeConn) Login(context.Context, string, string) (authn.Identity, bool, error) {
	return f.id, f.ok, f.err
}

func TestLoginViaConnectorProvisionsAndAuthenticates(t *testing.T) {
	srv := testServer(t)
	// An admin must already exist or /login redirects to /setup.
	createUser(t, srv, "admin", "Sup3r$ecretPW!", true)
	srv.connectors = []authn.PasswordConnector{fakeConn{
		ok: true,
		id: authn.Identity{Connector: "ldap", ExternalID: "uid=jane,dc=x",
			Username: "jane", Email: "jane@x", DisplayName: "Jane", IsAdmin: true},
	}}

	form := url.Values{"username": {"jane"}, "password": {"whatever"}, "csrf_token": {"tok"}}
	rr := do(srv, postForm("/login", form, "tok"))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303 on LDAP login, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) == "" {
		t.Fatal("expected a session cookie after LDAP login")
	}

	u, err := srv.db.GetUserByUsername(context.Background(), "jane")
	if err != nil {
		t.Fatalf("user not provisioned: %v", err)
	}
	if u.AuthSource != "ldap" || !u.IsAdmin || u.ExternalID != "uid=jane,dc=x" {
		t.Fatalf("bad provisioned user: %+v", u)
	}
}

func TestLoginConnectorRejectIsGenericInvalid(t *testing.T) {
	srv := testServer(t)
	createUser(t, srv, "admin", "Sup3r$ecretPW!", true)
	srv.connectors = []authn.PasswordConnector{fakeConn{ok: false}}

	form := url.Values{"username": {"ghost"}, "password": {"x"}, "csrf_token": {"tok"}}
	rr := do(srv, postForm("/login", form, "tok"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if sessionCookie(rr) != "" {
		t.Fatal("must not set a session on connector reject")
	}
}

func TestLoginLocalUserUnaffectedByConnector(t *testing.T) {
	srv := testServer(t)
	// A connector that would reject everything must not break local login.
	srv.connectors = []authn.PasswordConnector{fakeConn{ok: false}}
	createUser(t, srv, "bob", "Sup3r$ecretPW!", false)

	form := url.Values{"username": {"bob"}, "password": {"Sup3r$ecretPW!"}, "csrf_token": {"tok"}}
	rr := do(srv, postForm("/login", form, "tok"))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("local login broke with connectors present: %d (body: %s)", rr.Code, rr.Body.String())
	}
	if sessionCookie(rr) == "" {
		t.Fatal("expected a session cookie for local login")
	}
}

// --- local-password flows are disabled for directory-managed users ---

func TestForgotSkipsDirectoryUser(t *testing.T) {
	srv := testServer(t)
	ms := newMockSender()
	srv.mailer = ms
	ctx := context.Background()
	if _, err := srv.db.UpsertExternalUser(ctx, "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false); err != nil {
		t.Fatal(err)
	}

	// A reset request for the LDAP user must not dispatch any email/token.
	srv.dispatchReset("jane@x", "1.2.3.4", "test")
	select {
	case e := <-ms.sent:
		t.Fatalf("directory user should get no reset email, got %+v", e)
	default:
	}

	// Sanity: a local user still does.
	createUser(t, srv, "bob", "Sup3r$ecretPW!", false)
	srv.dispatchReset("bob", "1.2.3.4", "test")
	select {
	case <-ms.sent: // good
	default:
		t.Fatal("local user should receive a reset email")
	}
}

func TestAccountPasswordBlockedForDirectoryUser(t *testing.T) {
	srv := testServer(t)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}
	sid := startSession(t, srv, u.ID)
	rr := adminPost(srv, "/account/password", url.Values{
		"current_password": {"x"}, "new_password": {"N3w$ecretPW!!"},
	}, sid)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403 for directory user, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestAdminResetLinkBlockedForDirectoryUser(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}
	rr := adminPost(srv, "/admin/users/"+u.ID+"/reset-link", url.Values{}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for directory user, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}
