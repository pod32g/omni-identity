package enrollment_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/enrollment"
	"github.com/pod32g/omni-identity/internal/model"
)

// signIn runs SignIn for uid, approving the grant as the seeded user, and
// returns the cache and the events in the order they were reported.
func signIn(t *testing.T, ti *testIssuer, agent *enrollment.Agent, uid int) (*enrollment.UserCache, []enrollment.SignInEvent) {
	t.Helper()
	type result struct {
		uc  *enrollment.UserCache
		err error
	}
	events := make(chan enrollment.SignInEvent, 4)
	done := make(chan result, 1)
	go func() {
		uc, err := agent.SignIn(context.Background(), uid, func(ev enrollment.SignInEvent) { events <- ev })
		done <- result{uc, err}
	}()
	ti.approvePending(t)
	res := <-done
	if res.err != nil {
		t.Fatalf("signin: %v", res.err)
	}
	close(events)
	var got []enrollment.SignInEvent
	for ev := range events {
		got = append(got, ev)
	}
	return res.uc, got
}

// A desktop sign-in stores the device-bound refresh token under the caller's
// own uid: no local secret, no uid allocation, no home directory.
func TestSignInStoresDeviceBoundCache(t *testing.T) {
	ti, agent := enrolledAgent(t, nil)
	const uid = 501
	uc, events := signIn(t, ti, agent, uid)
	st, _ := enrollment.LoadState(agent.StateDir)
	if uc.Username != "alice" || uc.Sub != ti.User.ID || uc.UID != uid || uc.GID != uid || uc.Home != "" || uc.SecretHash != "" {
		t.Errorf("cache = %+v", uc)
	}
	if uc.RefreshToken == "" || uc.DeviceID != st.DeviceID || uc.AMR != "pwd" || uc.Revoked || uc.LastOnlineAuth.IsZero() {
		t.Errorf("cache = %+v", uc)
	}
	if len(events) != 2 || events[0].Kind != enrollment.SignInVerification || events[1].Kind != enrollment.SignInSignedIn {
		t.Fatalf("events = %+v", events)
	}
	if v := events[0]; v.UserCode == "" || !strings.Contains(v.VerificationURIComplete, "/device?user_code=") || v.VerificationURI == "" || v.ExpiresIn <= 0 {
		t.Errorf("verification event = %+v", v)
	}
	if s := events[1]; s.Username != "alice" || s.Sub != ti.User.ID || s.AMR != "pwd" {
		t.Errorf("signed_in event = %+v", s)
	}
	// The record on disk is what was returned.
	stored, err := agent.LoadUserCache("alice")
	if err != nil || stored == nil || stored.RefreshToken != uc.RefreshToken || stored.UID != uid {
		t.Errorf("stored = %+v err=%v", stored, err)
	}
	// The daemon's trust refresh works on such a cache.
	_, _, client, err := agent.Open()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	agent.RefreshUsers(context.Background(), client, func(string, ...any) {})
	after, _ := agent.LoadUserCache("alice")
	if after.Revoked || after.RefreshToken == "" || !after.LastTrustRefresh.After(uc.LastTrustRefresh) {
		t.Errorf("trust refresh: %+v", after)
	}
	// Signing in again as the same user refreshes the entry instead of failing.
	again, _ := signIn(t, ti, agent, uid)
	if again.Sub != uc.Sub || again.RefreshToken == "" || again.RefreshToken == after.RefreshToken || !again.LastOnlineAuth.After(uc.LastOnlineAuth) {
		t.Errorf("second signin = %+v", again)
	}
	if all, _ := agent.ListUserCaches(); len(all) != 1 {
		t.Errorf("caches = %d, want 1", len(all))
	}
}

// After a desktop sign-in the broker issues audience-bound tokens for the
// caller's uid, with the delegation claims and the admin's groups.
func TestSignInFeedsTheBroker(t *testing.T) {
	ti, agent := enrolledAgent(t, nil)
	now := time.Now().UTC()
	if err := ti.DB.CreateClient(context.Background(), &model.Client{ClientID: "omni-access", Name: "access", Type: model.ClientTypeConfidential,
		AllowedScopes: []string{"openid", "email", "profile"}, RedirectURIs: []string{"https://access/cb"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	ti.User.IsAdmin = true
	if err := ti.DB.UpdateUser(context.Background(), ti.User); err != nil {
		t.Fatal(err)
	}
	const uid = 501
	signIn(t, ti, agent, uid)
	pol := enrollment.BrokerPolicy{Audiences: []string{"omni-access"}}
	tok, err := agent.BrokerToken(context.Background(), uid, "omni-access", "", pol)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	claims, err := parseUnverified(tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := enrollment.LoadState(agent.StateDir)
	if claims["sub"] != ti.User.ID || claims["aud"] != "omni-access" || claims["device_id"] != st.DeviceID {
		t.Errorf("claims = %v", claims)
	}
	if act, _ := claims["act"].(map[string]any); act["sub"] != st.DeviceID {
		t.Errorf("act = %v", claims["act"])
	}
	if groups, _ := claims["groups"].([]any); len(groups) != 1 || groups[0] != "admins" {
		t.Errorf("groups = %v", claims["groups"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Errorf("auth_time missing: %v", claims)
	}
	// Another uid on the same machine gets nothing.
	if _, err := agent.BrokerToken(context.Background(), uid+1, "omni-access", "", pol); err == nil || !strings.Contains(err.Error(), "not a signed-in") {
		t.Errorf("stranger: %v", err)
	}
}

// Sign-out revokes the refresh token at Omni and forgets the cache; whoami
// never shows the token.
func TestSignOutRevokesAndWhoamiHidesSecrets(t *testing.T) {
	ti, agent := enrolledAgent(t, nil)
	agent.Out = io.Discard
	const uid = 501
	if uc, err := agent.Whoami(uid); uc != nil || err != nil {
		t.Fatalf("whoami before signin = %+v err=%v", uc, err)
	}
	uc, _ := signIn(t, ti, agent, uid)
	who, err := agent.Whoami(uid)
	if err != nil || who == nil {
		t.Fatalf("whoami = %+v err=%v", who, err)
	}
	if who.RefreshToken != "" || who.SecretHash != "" || who.Username != "alice" || who.Sub != uc.Sub || who.UID != uid {
		t.Errorf("whoami = %+v", who)
	}
	// The copy is detached from the stored record.
	if stored, _ := agent.LoadUserCache("alice"); stored.RefreshToken == "" {
		t.Error("whoami blanked the stored token")
	}
	if uc, _ := agent.Whoami(uid + 1); uc != nil {
		t.Errorf("whoami for another uid = %+v", uc)
	}

	if err := agent.SignOut(context.Background(), uid); err != nil {
		t.Fatalf("signout: %v", err)
	}
	rt, err := ti.DB.GetRefreshTokenByHash(context.Background(), auth.HashToken(uc.RefreshToken))
	if err != nil || !rt.Revoked {
		t.Errorf("refresh token after signout: %+v err=%v", rt, err)
	}
	if stored, _ := agent.LoadUserCache("alice"); stored != nil {
		t.Errorf("cache survived signout: %+v", stored)
	}
	if who, _ := agent.Whoami(uid); who != nil {
		t.Errorf("whoami after signout = %+v", who)
	}
	if _, err := agent.BrokerToken(context.Background(), uid, "omni-access", "", enrollment.BrokerPolicy{Audiences: []string{"omni-access"}}); err == nil {
		t.Error("broker still issues after signout")
	}
	// Signing out when nothing is signed in is fine.
	if err := agent.SignOut(context.Background(), uid); err != nil {
		t.Errorf("second signout: %v", err)
	}
}

// A cached name that belongs to a different Omni user is never overwritten.
func TestSignInRefusesAnotherUsersName(t *testing.T) {
	ti, agent := enrolledAgent(t, nil)
	if err := agent.SaveUserCache(&enrollment.UserCache{Username: "alice", Sub: "someone-else", UID: 777}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := agent.SignIn(context.Background(), 501, nil)
		done <- err
	}()
	ti.approvePending(t)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "different Omni user") {
		t.Errorf("signin = %v", err)
	}
	if uc, _ := agent.LoadUserCache("alice"); uc == nil || uc.Sub != "someone-else" || uc.UID != 777 {
		t.Errorf("cache changed: %+v", uc)
	}
}
