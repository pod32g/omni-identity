package enrollment

import (
	"bufio"
	"context"
	"encoding/json"
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
//
// Two further operations serve a local management agent (Omni Endpoint
// Management) that must authenticate as the *device* rather than as a
// signed-in user, without ever loading the device key itself:
//
//	DEVICE <audience>                  -> TOKEN <expires_in> <device_token>
//	PROOF <method> <url> [<token>]     -> PROOF <dpop_proof>
//
// DEVICE performs the RFC 7523 jwt-bearer grant for the given audience (a
// registered Omni application) and returns the DPoP-bound device token;
// PROOF signs one RFC 9449 proof with the device key for a request the
// caller is about to make (bound to the token's hash when one is given).
// Both are answered only to a peer running as the daemon's own uid: a
// process that could read the key file anyway gains nothing new, and every
// other uid is refused. Neither needs broker_audiences: the daemon's own
// audience policy governs user tokens only.

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
	if len(pol.Audiences) == 0 {
		logf("token broker listening at %s (device operations only: no broker_audiences configured)", path)
	} else {
		logf("token broker listening at %s for audiences %v", path, pol.Audiences)
	}
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
	// Personal access tokens are managed with a JSON-framed verb because a
	// token name may contain spaces: "PAT {json}" → "OK {json}" / "ERR ...".
	if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "PAT "); ok {
		// User-token verbs keep their rule: no broker_audiences = off. The
		// socket may still be listening for the device operations below.
		if len(pol.Audiences) == 0 {
			reply("ERR the token broker is disabled on this machine (no broker_audiences configured)")
			return
		}
		a.handleBrokerPAT(ctx, uid, rest, pol, reply, logf)
		return
	}
	fields := strings.Fields(line)
	switch {
	case len(fields) >= 2 && fields[0] == "TOKEN":
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
	case len(fields) == 2 && fields[0] == "DEVICE":
		audience := fields[1]
		if !sameUID(uid) {
			logf("broker: uid=%d DEVICE %s refused: not the daemon's uid", uid, audience)
			reply("ERR device operations are only served to the daemon's own uid")
			return
		}
		tok, err := a.DeviceTokenFor(ctx, audience)
		if err != nil {
			logf("broker: DEVICE %s failed: %v", audience, err)
			reply("ERR " + err.Error())
			return
		}
		logf("broker: DEVICE %s issued (%ds)", audience, tok.ExpiresIn)
		reply(fmt.Sprintf("TOKEN %d %s", tok.ExpiresIn, tok.AccessToken))
	case (len(fields) == 3 || len(fields) == 4) && fields[0] == "PROOF":
		if !sameUID(uid) {
			logf("broker: uid=%d PROOF refused: not the daemon's uid", uid)
			reply("ERR device operations are only served to the daemon's own uid")
			return
		}
		token := ""
		if len(fields) == 4 {
			token = fields[3]
		}
		proof, err := a.SignProof(fields[1], fields[2], token)
		if err != nil {
			logf("broker: PROOF failed: %v", err)
			reply("ERR " + err.Error())
			return
		}
		reply("PROOF " + proof)
	default:
		reply("ERR usage: TOKEN <audience> [scope] | PAT {json} | DEVICE <audience> | PROOF <method> <url> [<token>]")
	}
}

// sameUID says whether a broker peer runs as the daemon itself. On Windows
// every process reports -1, and the socket lives inside the user's profile
// directory whose ACL is the guard (see peeruid_windows.go).
func sameUID(uid int) bool { return uid == os.Getuid() }

// DeviceTokenFor returns a DPoP-bound device token for the given audience,
// reusing the last one while it has more than a minute left. The token is
// held in memory only.
func (a *Agent) DeviceTokenFor(ctx context.Context, audience string) (*TokenResponse, error) {
	if audience == "" {
		return nil, errors.New("audience is required")
	}
	st, _, client, err := a.Open()
	if err != nil {
		return nil, err
	}
	a.audMu.Lock()
	defer a.audMu.Unlock()
	if a.audTok == nil {
		a.audTok = map[string]cachedToken{}
	}
	if c, ok := a.audTok[audience]; ok && time.Now().Before(c.expires.Add(-time.Minute)) {
		return &TokenResponse{AccessToken: c.token, ExpiresIn: int(time.Until(c.expires).Seconds()), TokenType: "DPoP"}, nil
	}
	tok, err := client.DeviceTokenFor(ctx, st.DeviceID, audience)
	if err != nil {
		return nil, err
	}
	a.audTok[audience] = cachedToken{token: tok.AccessToken, expires: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)}
	return tok, nil
}

// SignProof signs one DPoP proof with the device key for a request the
// caller is about to make (method + URL, optionally bound to the token).
func (a *Agent) SignProof(method, target, token string) (string, error) {
	if method == "" || target == "" {
		return "", errors.New("method and url are required")
	}
	if u, err := url.Parse(target); err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("url must be absolute")
	}
	_, _, client, err := a.Open()
	if err != nil {
		return "", err
	}
	return client.proof(strings.ToUpper(method), target, token)
}

type cachedToken struct {
	token   string
	expires time.Time
}

// RequestDeviceToken is the client side of DEVICE: it asks the daemon for a
// device token audienced at the given application. Only the daemon's own
// uid is served.
func RequestDeviceToken(runtimeDir, audience string) (token string, expiresIn int, err error) {
	line, err := brokerRoundTrip(runtimeDir, "DEVICE "+audience)
	if err != nil {
		return "", 0, err
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "TOKEN" {
		return "", 0, errors.New(strings.TrimSpace(strings.TrimPrefix(line, "ERR ")))
	}
	var n int
	_, _ = fmt.Sscanf(fields[1], "%d", &n)
	return fields[2], n, nil
}

// RequestProof is the client side of PROOF.
func RequestProof(runtimeDir, method, target, token string) (string, error) {
	req := "PROOF " + method + " " + target
	if token != "" {
		req += " " + token
	}
	line, err := brokerRoundTrip(runtimeDir, req)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "PROOF" {
		return "", errors.New(strings.TrimSpace(strings.TrimPrefix(line, "ERR ")))
	}
	return fields[1], nil
}

func brokerRoundTrip(runtimeDir, request string) (string, error) {
	conn, err := net.DialTimeout("unix", filepath.Join(runtimeDir, BrokerSocketName), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("broker unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte(request + "\n")); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(line) == "" {
		return "", errors.New("empty reply")
	}
	return line, nil
}

// brokerPATRequest is the JSON payload after the PAT verb.
type brokerPATRequest struct {
	Action    string `json:"action"` // create | list | revoke
	Audience  string `json:"audience,omitempty"`
	Name      string `json:"name,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	ID        string `json:"id,omitempty"`
}

func (a *Agent) handleBrokerPAT(ctx context.Context, uid int, payload string, pol BrokerPolicy, reply func(string), logf func(string, ...any)) {
	var req brokerPATRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		reply("ERR malformed PAT request")
		return
	}
	replyJSON := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			reply("ERR " + err.Error())
			return
		}
		reply("OK " + string(b))
	}
	switch req.Action {
	case "create":
		pat, err := a.BrokerCreatePAT(ctx, uid, req.Name, req.Audience, req.Scope, req.ExpiresIn, pol)
		if err != nil {
			logf("broker: uid=%d pat.create refused: %v", uid, err)
			reply("ERR " + err.Error())
			return
		}
		logf("broker: uid=%d pat.create issued %s", uid, pat.ID)
		replyJSON(pat)
	case "list":
		list, err := a.BrokerListPATs(ctx, uid)
		if err != nil {
			reply("ERR " + err.Error())
			return
		}
		replyJSON(map[string]any{"tokens": list})
	case "revoke":
		if err := a.BrokerRevokePAT(ctx, uid, req.ID); err != nil {
			reply("ERR " + err.Error())
			return
		}
		replyJSON(map[string]any{"revoked": req.ID})
	default:
		reply("ERR unknown PAT action")
	}
}

// brokerUserClient resolves the signed-in user owning uid and opens the device
// client, returning the refresh token and a fresh device token — the shared
// preamble of every brokered personal-access-token operation.
func (a *Agent) brokerUserClient(ctx context.Context, uid int) (refreshToken, deviceToken string, client *Client, err error) {
	if privilegedUID(uid) {
		return "", "", nil, errors.New("root and system processes cannot use the broker")
	}
	users, err := a.ListUserCaches()
	if err != nil {
		return "", "", nil, err
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
		return "", "", nil, errors.New("caller is not a signed-in Omni user")
	case uc.Revoked:
		return "", "", nil, errors.New("this device's access for the caller was revoked")
	case uc.RefreshToken == "":
		return "", "", nil, errors.New("caller has not signed in online on this device")
	}
	st, _, client, err := a.Open()
	if err != nil {
		return "", "", nil, err
	}
	devTok, err := a.cachedDeviceToken(ctx, client, st.DeviceID)
	if err != nil {
		return "", "", nil, err
	}
	return uc.RefreshToken, devTok, client, nil
}

// BrokerCreatePAT creates a device-bound personal access token for the user
// owning uid. The audience must be allowed by the machine's broker policy,
// the same gate as a brokered exchange token.
func (a *Agent) BrokerCreatePAT(ctx context.Context, uid int, name, audience, scope string, expiresIn int, pol BrokerPolicy) (*PersonalAccessToken, error) {
	if !pol.allows(audience) {
		return nil, errors.New("audience is not allowed by this machine's broker policy")
	}
	rt, devTok, client, err := a.brokerUserClient(ctx, uid)
	if err != nil {
		return nil, err
	}
	return client.CreatePAT(ctx, devTok, rt, name, audience, scope, expiresIn)
}

func (a *Agent) BrokerListPATs(ctx context.Context, uid int) ([]PersonalAccessToken, error) {
	_, devTok, client, err := a.brokerUserClient(ctx, uid)
	if err != nil {
		return nil, err
	}
	return client.ListPATs(ctx, devTok)
}

func (a *Agent) BrokerRevokePAT(ctx context.Context, uid int, id string) error {
	_, devTok, client, err := a.brokerUserClient(ctx, uid)
	if err != nil {
		return err
	}
	return client.RevokePAT(ctx, devTok, id)
}

// BrokerToken performs the exchange for the user owning uid.
func (a *Agent) BrokerToken(ctx context.Context, uid int, audience, scope string, pol BrokerPolicy) (*TokenResponse, error) {
	if !pol.allows(audience) {
		return nil, errors.New("audience is not allowed by this machine's broker policy")
	}
	if privilegedUID(uid) {
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
