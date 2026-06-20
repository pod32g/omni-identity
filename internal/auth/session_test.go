package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
	"github.com/pod32g/omni-identity/internal/store"
)

func testStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func makeUser(t *testing.T, db *store.DB) *model.User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u := &model.User{
		ID:           uuid.NewString(),
		Username:     "u-" + uuid.NewString()[:8],
		Email:        uuid.NewString()[:8] + "@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestIssueSetsCookieAndPersistsSession(t *testing.T) {
	db := testStore(t)
	sm := NewSessionManager(db, false, time.Hour)
	u := makeUser(t, db)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	sess, err := sm.Issue(rr, req, u.ID, "pwd")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("session cookie not set")
	}
	if cookie.Value != sess.ID {
		t.Errorf("cookie value %q != session id %q", cookie.Value, sess.ID)
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie must be SameSite=Lax")
	}
}

func TestCurrentReturnsIssuedSession(t *testing.T) {
	db := testStore(t)
	sm := NewSessionManager(db, false, time.Hour)
	u := makeUser(t, db)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	sess, _ := sm.Issue(rr, req, u.ID, "pwd")

	next := httptest.NewRequest(http.MethodGet, "/admin", nil)
	next.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})

	got, err := sm.Current(next)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("user id = %q, want %q", got.UserID, u.ID)
	}
}

func TestCurrentNoCookieReturnsErrNoSession(t *testing.T) {
	db := testStore(t)
	sm := NewSessionManager(db, false, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	if _, err := sm.Current(req); !errors.Is(err, ErrNoSession) {
		t.Errorf("err = %v, want ErrNoSession", err)
	}
}

func TestDestroyDeletesSessionAndClearsCookie(t *testing.T) {
	db := testStore(t)
	sm := NewSessionManager(db, false, time.Hour)
	u := makeUser(t, db)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	sess, _ := sm.Issue(rr, req, u.ID, "pwd")

	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	logoutRR := httptest.NewRecorder()
	if err := sm.Destroy(logoutRR, logoutReq); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// Session must be gone from the store.
	check := httptest.NewRequest(http.MethodGet, "/admin", nil)
	check.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	if _, err := sm.Current(check); !errors.Is(err, ErrNoSession) {
		t.Errorf("session should be destroyed, err = %v", err)
	}
}

func TestCSRFForSessionMethods(t *testing.T) {
	sess := &model.Session{CSRFSecret: "abc"}
	if !ValidateSessionCSRF(sess, "abc") {
		t.Error("matching session csrf should validate")
	}
	if ValidateSessionCSRF(sess, "nope") {
		t.Error("mismatched session csrf must not validate")
	}
}
