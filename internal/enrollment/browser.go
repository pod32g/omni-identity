package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Browser-based enrollment (RFC 8252 §7.3): authorization code + PKCE through
// the system browser with a loopback redirect on an ephemeral port. The
// server ignores the port for the built-in client's registered
// http://127.0.0.1/callback (migration 0015). The token request carries a
// DPoP proof, so the resulting access token is bound to the device key exactly
// as in the device-grant path; steps 5-6 of the ceremony are shared.

// AuthorizeViaBrowser runs the code flow and returns the DPoP-bound token
// response. openURL is called with the authorization URL (nil = print only).
func (c *Client) AuthorizeViaBrowser(ctx context.Context, scope string, openURL func(string) error, notify func(string)) (*TokenResponse, error) {
	if _, err := c.discover(ctx); err != nil {
		return nil, err
	}
	authz := strings.TrimRight(c.Issuer, "/") + "/oauth2/authorize"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("loopback listener: %w", err)
	}
	defer l.Close()
	redirect := "http://127.0.0.1:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port) + "/callback"

	verifier := randomID() + randomID()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomID()
	nonce := randomID()

	q := url.Values{
		"response_type": {"code"}, "client_id": {c.ClientID}, "redirect_uri": {redirect},
		"scope": {scope}, "state": {state}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	authURL := authz + "?" + q.Encode()

	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		qs := r.URL.Query()
		if qs.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			got <- result{err: errors.New("state mismatch on callback")}
			return
		}
		if e := qs.Get("error"); e != "" {
			http.Error(w, "sign-in failed: "+e, http.StatusBadRequest)
			got <- result{err: fmt.Errorf("authorization refused: %s (%s)", e, qs.Get("error_description"))}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Omni Identity</title><body style=\"font-family:system-ui;padding:2rem\"><h2>Device enrollment authorized.</h2><p>You can close this tab and return to the terminal.</p></body>"))
		got <- result{code: qs.Get("code")}
	})
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	if notify != nil {
		notify(authURL)
	}
	if openURL != nil {
		if err := openURL(authURL); err != nil && notify != nil {
			notify("could not open a browser: " + err.Error())
		}
	}

	var res result
	select {
	case res = <-got:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if res.err != nil {
		return nil, res.err
	}
	if res.code == "" {
		return nil, errors.New("callback carried no code")
	}
	return c.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {redirect},
		"client_id":     {c.ClientID},
		"code_verifier": {verifier},
	}, "")
}

// OpenBrowser launches the platform's URL opener without a shell.
func OpenBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		// Under sudo/pkexec, open the page as the desktop user: root has no
		// display session or browser profile of its own.
		if u := desktopUser(); u != nil {
			return openAsUser(u, target)
		}
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

// randomID returns 128 bits of base64url randomness (PKCE verifier halves,
// state, nonce).
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("enrollment: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
