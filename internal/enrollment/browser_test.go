package enrollment_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pod32g/omni-identity/internal/enrollment"
)

// TestBrowserEnrollmentRFC8252 drives the --browser path: the "browser" is a
// cookie-carrying HTTP client signed in as alice that follows the
// authorization redirect, approves consent, and lands on the agent's
// ephemeral loopback listener; the token exchange uses PKCE + DPoP.
func TestBrowserEnrollmentRFC8252(t *testing.T) {
	ti := newTestIssuer(t)
	var out bytes.Buffer
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "s"), RuntimeDir: filepath.Join(t.TempDir(), "r"), Out: &out}

	browser := func(authURL string) error {
		go func() {
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			get := func(u string) *http.Response {
				req, _ := http.NewRequest(http.MethodGet, u, nil)
				req.AddCookie(&http.Cookie{Name: "omni_session", Value: ti.SID})
				req.AddCookie(&http.Cookie{Name: "omni_csrf", Value: "csrf"})
				resp, err := client.Do(req)
				if err != nil {
					t.Error(err)
					return nil
				}
				return resp
			}
			// 1. authorize → parked consent request (built-in client requires consent).
			resp := get(authURL)
			if resp == nil || resp.StatusCode != http.StatusSeeOther {
				t.Errorf("authorize = %v", resp)
				return
			}
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if !strings.HasPrefix(loc, "/consent?req=") {
				t.Errorf("expected consent redirect, got %s", loc)
				return
			}
			reqID := strings.TrimPrefix(loc, "/consent?req=")
			// 2. consent page renders the device scope, then allow.
			page := get(ti.URL + loc)
			body, _ := io.ReadAll(page.Body)
			page.Body.Close()
			if !strings.Contains(string(body), "device:enroll") {
				t.Errorf("consent page lacks the scope: %s", body)
			}
			form := url.Values{"csrf_token": {"csrf"}, "req": {reqID}, "action": {"allow"}}
			preq, _ := http.NewRequest(http.MethodPost, ti.URL+"/consent", strings.NewReader(form.Encode()))
			preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			preq.AddCookie(&http.Cookie{Name: "omni_session", Value: ti.SID})
			preq.AddCookie(&http.Cookie{Name: "omni_csrf", Value: "csrf"})
			cresp, err := client.Do(preq)
			if err != nil {
				t.Error(err)
				return
			}
			cb := cresp.Header.Get("Location")
			cresp.Body.Close()
			if !regexp.MustCompile(`^http://127\.0\.0\.1:\d+/callback\?`).MatchString(cb) {
				t.Errorf("unexpected callback redirect %q", cb)
				return
			}
			// 3. the browser lands on the agent's loopback listener.
			lr, err := http.Get(cb)
			if err != nil {
				t.Error(err)
				return
			}
			lr.Body.Close()
		}()
		return nil
	}

	st, err := agent.Enroll(context.Background(), enrollment.Config{Issuer: ti.URL, AllowInsecureHTTP: true, Browser: true, OpenURL: browser})
	if err != nil {
		t.Fatalf("browser enrollment: %v\n%s", err, out.String())
	}
	if st.OwnerSub != ti.User.ID || st.Status != "active" {
		t.Errorf("state = %+v", st)
	}
	dev, err := ti.DB.GetDevice(context.Background(), st.DeviceID)
	if err != nil || dev.Fingerprint != st.Fingerprint {
		t.Errorf("device = %+v err=%v", dev, err)
	}
	// The subsequent device authentication works exactly as with the device grant.
	if _, tok, err := agent.Renew(context.Background()); err != nil || tok.TokenType != "DPoP" {
		t.Errorf("renew after browser enrollment: %v", err)
	}
}
