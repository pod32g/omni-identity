package enrollment

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Local token broker (docs/DEVICE-IDENTITY-ARCHITECTURE.md §10). A local
// process connects to broker.sock and asks for a token for an audience; the
// daemon identifies the caller by its uid (SO_PEERCRED), maps it to a cached
// Omni user with a live device-bound refresh token, checks the audience
// against the operator's allowlist, and performs RFC 8693 token exchange at
// Omni with the device as actor. The app receives a short-lived,
// audience-bound bearer token and never sees a refresh token or the device
// key. Nothing is brokered for uids without a cached login, for audiences not
// on the allowlist, or when the user's trust is revoked.
//
// Protocol: request "TOKEN <audience> [scope]", reply
// "TOKEN <expires_in> <access_token>" or "ERR <reason>".

// BrokerSocketName is the socket file under the runtime dir.
const BrokerSocketName = "broker.sock"

// BrokerPolicy is the operator's allowlist.
type BrokerPolicy struct {
	// Audiences lists the client ids (audiences) local apps may request. Empty
	// disables the broker entirely.
	Audiences []string
}

func (p BrokerPolicy) allows(audience string) bool {
	for _, a := range p.Audiences {
		if a == audience {
			return true
		}
	}
	return false
}

// PeerUID resolves the uid of a connecting process (SO_PEERCRED on Linux).
// Tests override it.
type PeerUID func(conn *net.UnixConn) (int, error)

// ServeBroker listens on the broker socket until ctx is cancelled.
func (a *Agent) ServeBroker(ctx context.Context, pol BrokerPolicy, peer PeerUID, logf func(string, ...any)) error {
	if len(pol.Audiences) == 0 {
		logf("token broker disabled (no broker_audiences configured)")
		return nil
	}
	if peer == nil {
		peer = peerUID
	}
	if err := os.MkdirAll(a.RuntimeDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(a.RuntimeDir, BrokerSocketName)
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	logf("token broker listening at %s for audiences %v", path, pol.Audiences)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go a.handleBrokerConn(ctx, conn, pol, peer, logf)
	}
}

func (a *Agent) handleBrokerConn(ctx context.Context, conn net.Conn, pol BrokerPolicy, peer PeerUID, logf func(string, ...any)) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reply := func(s string) { _, _ = conn.Write([]byte(s + "\n")) }
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		reply("ERR not a unix socket")
		return
	}
	uid, err := peer(uc)
	if err != nil {
		reply("ERR peer credentials unavailable")
		return
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "TOKEN" {
		reply("ERR usage: TOKEN <audience> [scope]")
		return
	}
	audience := fields[1]
	scope := strings.Join(fields[2:], " ")
	tok, err := a.BrokerToken(ctx, uid, audience, scope, pol)
	if err != nil {
		logf("broker: uid=%d audience=%s refused: %v", uid, audience, err)
		reply("ERR " + err.Error())
		return
	}
	logf("broker: uid=%d audience=%s issued (%ds)", uid, audience, tok.ExpiresIn)
	reply(fmt.Sprintf("TOKEN %d %s", tok.ExpiresIn, tok.AccessToken))
}

// BrokerToken performs the exchange for the user owning uid.
func (a *Agent) BrokerToken(ctx context.Context, uid int, audience, scope string, pol BrokerPolicy) (*TokenResponse, error) {
	if !pol.allows(audience) {
		return nil, errors.New("audience is not allowed by this machine's broker policy")
	}
	if uid <= 0 {
		return nil, errors.New("root and system processes cannot use the broker")
	}
	users, err := a.ListUserCaches()
	if err != nil {
		return nil, err
	}
	var uc *UserCache
	for _, u := range users {
		if u.UID == uid {
			uc = u
			break
		}
	}
	switch {
	case uc == nil:
		return nil, errors.New("caller is not a signed-in Omni user")
	case uc.Revoked:
		return nil, errors.New("this device's access for the caller was revoked")
	case uc.RefreshToken == "":
		return nil, errors.New("caller has not signed in online on this device")
	}
	st, _, client, err := a.Open()
	if err != nil {
		return nil, err
	}
	devTok, err := a.cachedDeviceToken(ctx, client, st.DeviceID)
	if err != nil {
		return nil, err
	}
	tok, err := client.ExchangeToken(ctx, uc.RefreshToken, devTok, audience, scope)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// ExchangeToken performs RFC 8693 token exchange: subject = the user's
// device-bound refresh token, actor = this device's token, both proven by the
// device key's DPoP proof.
func (c *Client) ExchangeToken(ctx context.Context, refreshToken, deviceToken, audience, scope string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {c.ClientID},
		"subject_token":      {refreshToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
		"actor_token":        {deviceToken},
		"actor_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {audience},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.tokenRequest(ctx, form, "")
}

// RequestBrokerToken is the client side used by `omni-enrollment token`: it
// connects to the broker socket as the calling user.
func RequestBrokerToken(runtimeDir, audience, scope string) (token string, expiresIn int, err error) {
	conn, err := net.DialTimeout("unix", filepath.Join(runtimeDir, BrokerSocketName), 5*time.Second)
	if err != nil {
		return "", 0, fmt.Errorf("broker unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := "TOKEN " + audience
	if scope != "" {
		req += " " + scope
	}
	if _, err := conn.Write([]byte(req + "\n")); err != nil {
		return "", 0, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return "", 0, errors.New("empty reply")
	}
	if fields[0] != "TOKEN" || len(fields) != 3 {
		return "", 0, errors.New(strings.TrimSpace(strings.TrimPrefix(line, "ERR ")))
	}
	var n int
	_, _ = fmt.Sscanf(fields[1], "%d", &n)
	return fields[2], n, nil
}
