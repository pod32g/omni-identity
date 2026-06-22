package ldap

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/authn"
)

func TestRenderFilterEscapes(t *testing.T) {
	got := renderFilter("(uid=%s)", `ja*ne)(uid=*`)
	want := `(uid=ja\2ane\29\28uid=\2a)`
	if got != want {
		t.Fatalf("escape failed:\n got=%s\nwant=%s", got, want)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty url must error")
	}
	if _, err := New(Config{URL: "ldap://h", BaseDN: "dc=x", UserFilter: "(uid=foo)"}); err == nil {
		t.Fatal("user_filter without a username placeholder must error")
	}
	if _, err := New(Config{URL: "ldap://h", BaseDN: "dc=x", UserFilter: "(uid=%s)"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestUserDNDefaultsAndEscaping(t *testing.T) {
	c, err := New(Config{URL: "ldap://h", BaseDN: "ou=people,dc=x", UserFilter: "(uid=%s)"})
	if err != nil {
		t.Fatal(err)
	}
	// RDNAttr defaults to AttrUsername (uid) and PeopleBaseDN to BaseDN.
	if got := c.userDN("jane"); got != "uid=jane,ou=people,dc=x" {
		t.Fatalf("userDN = %q", got)
	}
	// A value with DN metacharacters must be escaped, never injected raw.
	got := c.userDN("ev,il+x")
	if strings.Contains(got, "uid=ev,il") || !strings.HasSuffix(got, ",ou=people,dc=x") {
		t.Fatalf("userDN did not escape the RDN value: %q", got)
	}
}

func TestImplementsDirectoryManager(t *testing.T) {
	var _ authn.DirectoryManager = (*Client)(nil)
}

func TestIDIsLDAP(t *testing.T) {
	c, _ := New(Config{URL: "ldap://h", BaseDN: "dc=x", UserFilter: "(uid=%s)"})
	if c.ID() != "ldap" {
		t.Fatalf("ID() = %q", c.ID())
	}
}

func TestLoginRejectsEmptyPassword(t *testing.T) {
	c, err := New(Config{URL: "ldap://localhost:389", BaseDN: "dc=x", UserFilter: "(uid=%s)"})
	if err != nil {
		t.Fatal(err)
	}
	// Must not even dial — empty password is rejected up front.
	id, ok, err := c.Login(context.Background(), "jane", "")
	if ok || err != nil || (id != authn.Identity{}) {
		t.Fatalf("empty password must be a clean negative: id=%+v ok=%v err=%v", id, ok, err)
	}
}

// TestLoginIntegration exercises a real directory. It is skipped unless
// OMNI_TEST_LDAP_URL is set (mirrors the gated postgres integration test).
func TestLoginIntegration(t *testing.T) {
	url := os.Getenv("OMNI_TEST_LDAP_URL")
	if url == "" {
		t.Skip("set OMNI_TEST_LDAP_URL to run the LDAP integration test")
	}
	c, err := New(Config{
		URL:             url,
		BindDN:          os.Getenv("OMNI_TEST_LDAP_BIND_DN"),
		BindPassword:    os.Getenv("OMNI_TEST_LDAP_BIND_PASSWORD"),
		BaseDN:          os.Getenv("OMNI_TEST_LDAP_BASE_DN"),
		UserFilter:      "(uid=%s)",
		AttrUsername:    "uid",
		AttrEmail:       "mail",
		AttrDisplayName: "cn",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, ok, err := c.Login(context.Background(),
		os.Getenv("OMNI_TEST_LDAP_USER"), os.Getenv("OMNI_TEST_LDAP_PASSWORD"))
	if err != nil {
		t.Fatalf("login error: %v", err)
	}
	if !ok || id.Username == "" {
		t.Fatalf("expected a valid identity, got ok=%v id=%+v", ok, id)
	}
}
