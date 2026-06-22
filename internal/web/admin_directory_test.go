package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/authn"
	"github.com/pod32g/omni-identity/internal/store"
)

// fakeDir is an in-memory DirectoryManager that records the last write of each
// kind and can be told to fail any one of them.
type fakeDir struct {
	created   authn.DirectoryUser
	createdDN string
	updatedDN string
	updated   authn.DirectoryUser
	pwDN, pw  string
	deletedDN string

	createErr, updateErr, pwErr, deleteErr error
}

func (*fakeDir) ID() string { return "ldap" }

func (f *fakeDir) CreateUser(_ context.Context, u authn.DirectoryUser) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = u
	f.createdDN = "uid=" + u.Username + ",ou=people,dc=x"
	return f.createdDN, nil
}

func (f *fakeDir) UpdateUser(_ context.Context, dn string, u authn.DirectoryUser) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updatedDN, f.updated = dn, u
	return nil
}

func (f *fakeDir) SetPassword(_ context.Context, dn, pw string) error {
	if f.pwErr != nil {
		return f.pwErr
	}
	f.pwDN, f.pw = dn, pw
	return nil
}

func (f *fakeDir) DeleteUser(_ context.Context, dn string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedDN = dn
	return nil
}

// enableDirectory makes srv write-capable (dir) and flips the live
// ldap_manage_enabled setting on, mirroring a configured + toggled-on deployment.
func enableDirectory(t *testing.T, srv *Server, dir authn.DirectoryManager) {
	t.Helper()
	srv.directory = dir
	v := srv.settings.Current()
	v.LDAPManageEnabled = true
	if err := srv.db.UpdateSettings(context.Background(), v.toModel()); err != nil {
		t.Fatalf("enable directory management: %v", err)
	}
	srv.settings.Reload(context.Background())
}

func TestAdminCreateDirectoryUser(t *testing.T) {
	srv := testServer(t)
	dir := &fakeDir{}
	enableDirectory(t, srv, dir)
	sid := adminSession(t, srv)

	rr := adminPost(srv, "/admin/users", url.Values{
		"source": {"ldap"}, "username": {"jane"}, "email": {"jane@x.test"},
		"display_name": {"Jane Doe"}, "password": {"Sup3r$ecretPW!"},
	}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if dir.created.Username != "jane" || dir.created.Email != "jane@x.test" || dir.created.DisplayName != "Jane Doe" {
		t.Fatalf("directory create not called with the form values: %+v", dir.created)
	}
	if dir.pwDN != dir.createdDN || dir.pw != "Sup3r$ecretPW!" {
		t.Fatalf("initial password not set on the new DN: dn=%q pw=%q", dir.pwDN, dir.pw)
	}
	// The mirror row exists immediately, before any login.
	u, err := srv.db.GetUserByUsername(context.Background(), "jane")
	if err != nil {
		t.Fatalf("mirror row not created: %v", err)
	}
	if u.AuthSource != "ldap" || u.ExternalID != dir.createdDN || u.IsAdmin {
		t.Fatalf("bad mirror row: %+v", u)
	}
}

func TestAdminCreateDirectoryUserDirectoryErrorLeavesNoMirror(t *testing.T) {
	srv := testServer(t)
	enableDirectory(t, srv, &fakeDir{createErr: errors.New("entryAlreadyExists")})
	sid := adminSession(t, srv)

	rr := adminPost(srv, "/admin/users", url.Values{
		"source": {"ldap"}, "username": {"jane"}, "email": {"jane@x.test"},
	}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 on directory error, got %d", rr.Code)
	}
	if _, err := srv.db.GetUserByUsername(context.Background(), "jane"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mirror row must not exist after a failed directory create: %v", err)
	}
}

func TestAdminCreateDirectoryUserRequiresManagement(t *testing.T) {
	srv := testServer(t) // directory is nil
	sid := adminSession(t, srv)
	rr := adminPost(srv, "/admin/users", url.Values{
		"source": {"ldap"}, "username": {"jane"}, "email": {"jane@x.test"},
	}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when management is off, got %d", rr.Code)
	}
}

func TestAdminSetDirectoryUserPassword(t *testing.T) {
	srv := testServer(t)
	dir := &fakeDir{}
	enableDirectory(t, srv, dir)
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}

	rr := adminPost(srv, "/admin/users/"+u.ID+"/password", url.Values{
		"password": {"An0ther$ecret!"}, "return": {"detail"},
	}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if dir.pwDN != "uid=jane,dc=x" || dir.pw != "An0ther$ecret!" {
		t.Fatalf("password not set in directory: dn=%q pw=%q", dir.pwDN, dir.pw)
	}
	// The mirror must remain passwordless — local hash is never the credential.
	got, _ := srv.db.GetUserByID(context.Background(), u.ID)
	if got.PasswordHash != "" {
		t.Fatalf("directory user must not gain a local hash, got %q", got.PasswordHash)
	}
}

func TestAdminSetDirectoryPasswordBlockedWhenManagementOff(t *testing.T) {
	srv := testServer(t) // directory is nil
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}
	rr := adminPost(srv, "/admin/users/"+u.ID+"/password", url.Values{
		"password": {"An0ther$ecret!"},
	}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 when management is off, got %d", rr.Code)
	}
}

func TestAdminUpdateDirectoryUser(t *testing.T) {
	srv := testServer(t)
	dir := &fakeDir{}
	enableDirectory(t, srv, dir)
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}

	rr := adminPost(srv, "/admin/users/"+u.ID+"/profile", url.Values{
		"email": {"jane.new@x.test"}, "display_name": {"Jane Q."}, "return": {"detail"},
	}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if dir.updatedDN != "uid=jane,dc=x" || dir.updated.Email != "jane.new@x.test" || dir.updated.DisplayName != "Jane Q." {
		t.Fatalf("directory not updated with form values: dn=%q %+v", dir.updatedDN, dir.updated)
	}
	got, _ := srv.db.GetUserByID(context.Background(), u.ID)
	if got.Email != "jane.new@x.test" {
		t.Fatalf("mirror email not refreshed, got %q", got.Email)
	}
}

func TestAdminDeleteDirectoryUser(t *testing.T) {
	srv := testServer(t)
	dir := &fakeDir{}
	enableDirectory(t, srv, dir)
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}

	rr := adminPost(srv, "/admin/users/"+u.ID+"/delete", url.Values{"return": {"detail"}}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if dir.deletedDN != "uid=jane,dc=x" {
		t.Fatalf("directory delete not issued for the DN, got %q", dir.deletedDN)
	}
	if _, err := srv.db.GetUserByID(context.Background(), u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mirror row must be gone after delete: %v", err)
	}
}

// A directory delete that fails must not remove the local mirror (directory-first).
func TestAdminDeleteDirectoryUserDirectoryErrorKeepsMirror(t *testing.T) {
	srv := testServer(t)
	enableDirectory(t, srv, &fakeDir{deleteErr: errors.New("server down")})
	sid := adminSession(t, srv)
	u, err := srv.db.UpsertExternalUser(context.Background(), "ldap", "uid=jane,dc=x", "jane", "jane@x", "Jane", false)
	if err != nil {
		t.Fatal(err)
	}
	rr := adminPost(srv, "/admin/users/"+u.ID+"/delete", url.Values{}, sid)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("want 502 on directory error, got %d", rr.Code)
	}
	if _, err := srv.db.GetUserByID(context.Background(), u.ID); err != nil {
		t.Fatalf("mirror must survive a failed directory delete: %v", err)
	}
}

func TestAdminDeleteLocalUser(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	victim := createUser(t, srv, "bob", "Sup3r$ecretPW!", false)

	rr := adminPost(srv, "/admin/users/"+victim.ID+"/delete", url.Values{}, sid)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if _, err := srv.db.GetUserByID(context.Background(), victim.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("local user row must be gone: %v", err)
	}
}

func TestAdminDeleteSelfBlocked(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	me, err := srv.db.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	rr := adminPost(srv, "/admin/users/"+me.ID+"/delete", url.Values{}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 deleting self, got %d", rr.Code)
	}
	if _, err := srv.db.GetUserByID(context.Background(), me.ID); err != nil {
		t.Fatalf("self account must survive a blocked delete: %v", err)
	}
}

// The create form offers a directory option only when management is enabled.
func TestUsersPageOffersDirectoryCreateOnlyWhenEnabled(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	if body := adminGet(srv, "/admin/users", sid).Body.String(); strings.Contains(body, "Directory user (LDAP)") {
		t.Fatal("directory create option shown without management enabled")
	}
	// Write-capable but toggle still off: the create option stays hidden.
	srv.directory = &fakeDir{}
	if body := adminGet(srv, "/admin/users", sid).Body.String(); strings.Contains(body, "Directory user (LDAP)") {
		t.Fatal("directory create option shown while the management toggle is off")
	}
	// Toggle on: the option appears.
	enableDirectory(t, srv, &fakeDir{})
	if body := adminGet(srv, "/admin/users", sid).Body.String(); !strings.Contains(body, "Directory user (LDAP)") {
		t.Fatal("directory create option missing when management enabled")
	}
}

// validSettingsForm is the minimal set of fields the system-settings form
// requires to validate (mirrors the live editable settings).
func validSettingsForm() url.Values {
	return url.Values{
		"issuer": {"http://localhost:8080"}, "public_url": {"http://localhost:8080"},
		"token_ttl": {"15m"}, "refresh_token_ttl": {"720h"}, "rate_limit_window": {"15m"},
		"login_ip_max_attempts": {"20"}, "password_verify_concurrency": {"4"},
		"max_login_username_bytes": {"320"}, "max_login_password_bytes": {"1024"},
		"allow_loopback_http_redirects": {"on"}, "lockout_duration": {"15m"},
		"session_lifetime": {"12h"}, "session_idle_timeout": {"0"},
		"max_failed_logins": {"5"}, "password_min_length": {"12"}, "max_logo_kib": {"512"},
	}
}

// The Settings page shows the management toggle only when write-capable, and
// posting it flips management live (no restart).
func TestSettingsManagementToggle(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)

	// Not write-capable (no bind): the toggle checkbox is absent.
	if body := adminGet(srv, "/admin/settings", sid).Body.String(); strings.Contains(body, `name="ldap_manage_enabled"`) {
		t.Fatal("management toggle shown without a write-capable bind")
	}

	// Write-capable: the toggle renders inside its own form posting to the
	// dedicated endpoint (the bug was a button with no enclosing form).
	srv.directory = &fakeDir{}
	body := adminGet(srv, "/admin/settings", sid).Body.String()
	if !strings.Contains(body, `name="ldap_manage_enabled"`) {
		t.Fatal("management toggle missing when write-capable")
	}
	if !strings.Contains(body, `action="/admin/settings/directory"`) {
		t.Fatal("management toggle not wired to its dedicated form action")
	}
	if srv.directoryEnabled() {
		t.Fatal("management should start disabled")
	}

	// Posting the dedicated toggle on enables management live.
	if rr := adminPost(srv, "/admin/settings/directory", url.Values{"ldap_manage_enabled": {"on"}}, sid); rr.Code != http.StatusSeeOther {
		t.Fatalf("enable toggle: code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !srv.directoryEnabled() {
		t.Fatal("management not enabled after posting the toggle on")
	}

	// Saving unrelated system settings must NOT disturb the toggle (it's not in
	// that form).
	if rr := adminPost(srv, "/admin/settings/system", validSettingsForm(), sid); rr.Code != http.StatusSeeOther {
		t.Fatalf("system save: code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	if !srv.directoryEnabled() {
		t.Fatal("system save wrongly disabled directory management")
	}

	// Posting the dedicated toggle without the checkbox turns it back off.
	if rr := adminPost(srv, "/admin/settings/directory", url.Values{}, sid); rr.Code != http.StatusSeeOther {
		t.Fatalf("disable toggle: code = %d", rr.Code)
	}
	if srv.directoryEnabled() {
		t.Fatal("management not disabled after posting the toggle off")
	}
}
