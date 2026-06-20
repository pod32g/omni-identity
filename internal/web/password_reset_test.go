package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockSender captures sent emails for assertions.
type mockSender struct {
	enabled bool
	mu      sync.Mutex
	sent    chan sentEmail
}

type sentEmail struct{ to, subject, body string }

func newMockSender() *mockSender    { return &mockSender{enabled: true, sent: make(chan sentEmail, 4)} }
func (m *mockSender) Enabled() bool { return m.enabled }
func (m *mockSender) Send(to, subject, body string) error {
	m.sent <- sentEmail{to, subject, body}
	return nil
}

// linkFromBody extracts the /set-password?token=… URL rendered in a page body.
func tokenFromLink(s string) string {
	i := strings.Index(s, "/set-password?token=")
	if i < 0 {
		return ""
	}
	rest := s[i+len("/set-password?token="):]
	for j := 0; j < len(rest); j++ {
		if rest[j] == '"' || rest[j] == '<' || rest[j] == ' ' || rest[j] == '\n' {
			return rest[:j]
		}
	}
	return rest
}

func TestInviteUserActivationFlow(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)

	// Create a user in invite mode → response shows a one-time setup link.
	rr := adminPost(srv, "/admin/users", url.Values{
		"username": {"newbie"}, "email": {"newbie@example.com"}, "invite": {"on"},
	}, sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("invite create code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	token := tokenFromLink(rr.Body.String())
	if token == "" {
		t.Fatalf("no setup link in response: %s", rr.Body.String())
	}

	// The new user cannot log in yet (no usable password).
	loginRR := do(srv, postForm("/login", url.Values{
		"username": {"newbie"}, "password": {"anything12345"}, "csrf_token": {"tok"},
	}, "tok"))
	if loginRR.Code != http.StatusUnauthorized {
		t.Errorf("invited user should not log in pre-activation: code=%d", loginRR.Code)
	}

	// GET set-password renders for a valid token.
	if got := do(srv, httptest.NewRequest(http.MethodGet, "/set-password?token="+token, nil)); got.Code != http.StatusOK {
		t.Fatalf("set-password GET code = %d", got.Code)
	}

	// Weak password rejected by policy (no number, default policy requires one).
	weak := postForm("/set-password", url.Values{
		"token": {token}, "password": {"alllowercase"}, "confirm": {"alllowercase"}, "csrf_token": {"tok"},
	}, "tok")
	if rr := do(srv, weak); rr.Code != http.StatusBadRequest {
		t.Errorf("weak password code = %d, want 400", rr.Code)
	}

	// Set a compliant password → redirect to login with the notice.
	good := postForm("/set-password", url.Values{
		"token": {token}, "password": {"GoodPass1234"}, "confirm": {"GoodPass1234"}, "csrf_token": {"tok"},
	}, "tok")
	setRR := do(srv, good)
	if setRR.Code != http.StatusSeeOther || setRR.Header().Get("Location") != "/login?notice=password-set" {
		t.Fatalf("set-password code=%d loc=%q", setRR.Code, setRR.Header().Get("Location"))
	}

	// Token is single-use.
	reuse := postForm("/set-password", url.Values{
		"token": {token}, "password": {"GoodPass1234"}, "confirm": {"GoodPass1234"}, "csrf_token": {"tok"},
	}, "tok")
	if rr := do(srv, reuse); rr.Code != http.StatusBadRequest {
		t.Errorf("reused token code = %d, want 400", rr.Code)
	}

	// User can now log in with the chosen password.
	ok := do(srv, postForm("/login", url.Values{
		"username": {"newbie"}, "password": {"GoodPass1234"}, "csrf_token": {"tok"},
	}, "tok"))
	if ok.Code != http.StatusSeeOther || sessionCookie(ok) == "" {
		t.Errorf("activated user login code = %d", ok.Code)
	}
}

func TestAdminResetLinkRevokesSessions(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	user := createUser(t, srv, "bob", "OldPass123", false)
	live := startSession(t, srv, user.ID)

	rr := adminPost(srv, "/admin/users/"+user.ID+"/reset-link", url.Values{}, sid)
	token := tokenFromLink(rr.Body.String())
	if token == "" {
		t.Fatalf("no reset link: %s", rr.Body.String())
	}

	set := postForm("/set-password", url.Values{
		"token": {token}, "password": {"BrandNew1234"}, "confirm": {"BrandNew1234"}, "csrf_token": {"tok"},
	}, "tok")
	if rr := do(srv, set); rr.Code != http.StatusSeeOther {
		t.Fatalf("reset set-password code = %d (body: %s)", rr.Code, rr.Body.String())
	}
	// Existing sessions for the user are revoked on password set.
	if _, err := srv.db.GetSession(context.Background(), live); err == nil {
		t.Error("user sessions should be revoked after a password reset")
	}
}

func TestForgotPasswordEnumerationSafeAndEmails(t *testing.T) {
	srv := testServer(t)
	mock := newMockSender()
	srv.mailer = mock
	createUser(t, srv, "alice", "OldPass123", false)

	// Existing account: generic response + an email is dispatched.
	rrReal := do(srv, postForm("/forgot", url.Values{"identifier": {"alice"}, "csrf_token": {"tok"}}, "tok"))
	if rrReal.Code != http.StatusOK || !strings.Contains(rrReal.Body.String(), "we've sent a reset link") {
		t.Fatalf("forgot (real) code=%d body=%s", rrReal.Code, rrReal.Body.String())
	}
	select {
	case msg := <-mock.sent:
		if !strings.Contains(msg.body, "/set-password?token=") {
			t.Errorf("reset email missing link: %q", msg.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a reset email for an existing account")
	}

	// Unknown account: identical response, and no email.
	rrFake := do(srv, postForm("/forgot", url.Values{"identifier": {"ghost"}, "csrf_token": {"tok"}}, "tok"))
	if rrFake.Body.String() != rrReal.Body.String() {
		t.Error("forgot response must be identical for unknown accounts (no enumeration)")
	}
	select {
	case <-mock.sent:
		t.Error("no email should be sent for an unknown account")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestForgotDisabledWithoutSMTP(t *testing.T) {
	srv := testServer(t) // default mailer has no host → disabled
	if got := do(srv, httptest.NewRequest(http.MethodGet, "/forgot", nil)); got.Code != http.StatusNotFound {
		t.Errorf("forgot without SMTP code = %d, want 404", got.Code)
	}
	createUser(t, srv, "admin", "pw", true)
	rr := do(srv, httptest.NewRequest(http.MethodGet, "/login", nil))
	if strings.Contains(rr.Body.String(), "/forgot") {
		t.Error("login should not show a forgot link when SMTP is disabled")
	}
}
