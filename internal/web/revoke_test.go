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

func seedRefreshToken(t *testing.T, srv *Server, raw, userID, clientID string) {
	t.Helper()
	now := time.Now().UTC()
	rt := &model.RefreshToken{
		ID:        uuid.NewString(),
		TokenHash: auth.HashToken(raw),
		ClientID:  clientID,
		UserID:    userID,
		Scope:     "openid offline_access",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}
	if err := srv.db.CreateRefreshToken(context.Background(), rt); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
}

func revokePost(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestRevokeRefreshToken(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "jellyfin", "secret", false,
		[]string{"https://x/cb"}, []string{"openid", "offline_access"})
	seedRefreshToken(t, srv, "rawrefresh", user.ID, "jellyfin")

	rr := do(srv, revokePost(url.Values{
		"token":         {"rawrefresh"},
		"client_id":     {"jellyfin"},
		"client_secret": {"secret"},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	got, _ := srv.db.GetRefreshTokenByHash(context.Background(), auth.HashToken("rawrefresh"))
	if !got.Revoked {
		t.Error("refresh token should be revoked")
	}
}

func TestRevokeRequiresClientAuth(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "secret", false,
		[]string{"https://x/cb"}, []string{"openid"})
	rr := do(srv, revokePost(url.Values{
		"token":         {"x"},
		"client_id":     {"jellyfin"},
		"client_secret": {"wrong"},
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rr.Code)
	}
}

func TestRevokeUnknownTokenReturns200(t *testing.T) {
	srv := testServer(t)
	createClient(t, srv, "jellyfin", "secret", false,
		[]string{"https://x/cb"}, []string{"openid"})
	rr := do(srv, revokePost(url.Values{
		"token":         {"does-not-exist"},
		"client_id":     {"jellyfin"},
		"client_secret": {"secret"},
	}))
	// RFC 7009: revoking an unknown token is still a success.
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", rr.Code)
	}
}

func TestRevokeOtherClientsTokenIsNoop(t *testing.T) {
	srv := testServer(t)
	user := createUser(t, srv, "alice", "pw", false)
	createClient(t, srv, "jellyfin", "secret", false, []string{"https://x/cb"}, []string{"openid"})
	createClient(t, srv, "other", "othersecret", false, []string{"https://y/cb"}, []string{"openid"})
	seedRefreshToken(t, srv, "victimtoken", user.ID, "jellyfin")

	// 'other' client tries to revoke jellyfin's token.
	rr := do(srv, revokePost(url.Values{
		"token":         {"victimtoken"},
		"client_id":     {"other"},
		"client_secret": {"othersecret"},
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	got, _ := srv.db.GetRefreshTokenByHash(context.Background(), auth.HashToken("victimtoken"))
	if got.Revoked {
		t.Error("a client must not revoke another client's token")
	}
}
