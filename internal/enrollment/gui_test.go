package enrollment_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
)

func TestGUIEnrollsAndManagesTheDevice(t *testing.T) {
	ti := newTestIssuer(t)
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "s"), RuntimeDir: filepath.Join(t.TempDir(), "r"), Out: io.Discard, NoHome: true}
	gui, err := enrollment.NewGUI(agent, enrollment.Config{Issuer: ti.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	launch, err := gui.Serve(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(launch)
	base := "http://" + u.Host
	token := u.Query().Get("t")

	// Without the token: refused. Wrong Host: refused.
	if resp, _ := http.Get(base + "/status"); resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no token should be forbidden: %v", resp)
	}
	req, _ := http.NewRequest(http.MethodGet, launch, nil)
	req.Host = "evil.example"
	if resp, _ := http.DefaultClient.Do(req); resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign host should be forbidden: %v", resp)
	}

	// The launch URL sets the cookie; the page renders.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(launch)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("launch: %v %v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Enroll this device") {
		t.Errorf("page: %s", body)
	}
	post := func(path string, form url.Values, withCSRF bool) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withCSRF {
			req.Header.Set("X-Omni-GUI", token)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// POST without the CSRF header is refused even with the cookie.
	if r := post("/enroll", url.Values{"issuer": {ti.URL}}, false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf: %d", r.StatusCode)
	}
	// Start the enrollment.
	r := post("/enroll", url.Values{"issuer": {ti.URL}, "name": {"gui-box"}, "key_backend": {"file"}, "allow_insecure_http": {"on"}}, true)
	if r.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("enroll = %d %s", r.StatusCode, b)
	}
	var started struct{ Link, Code string }
	_ = json.NewDecoder(r.Body).Decode(&started)
	r.Body.Close()
	if !strings.Contains(started.Link, "/device?user_code=") || started.Code == "" {
		t.Fatalf("started = %+v", started)
	}
	if qr, _ := client.Get(base + "/qr.svg"); qr == nil || qr.StatusCode != 200 || !strings.Contains(qr.Header.Get("Content-Type"), "svg") {
		t.Errorf("qr: %v", qr)
	}
	status := func() map[string]any {
		r, _ := client.Get(base + "/status")
		var v map[string]any
		_ = json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		return v
	}
	if v := status(); v["Phase"] != "waiting" || v["Code"] != started.Code {
		t.Fatalf("status = %v", v)
	}
	// The user approves at Omni; the page reaches "done" and shows the device.
	ti.approveAllPending(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		v := status()
		if v["Phase"] == "done" {
			if v["Enrolled"] != true || v["State"].(map[string]any)["name"] != "gui-box" {
				t.Fatalf("enrolled view = %v", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("enrollment did not finish: %v", v)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Manage: renew, rotate, unenroll.
	if r := post("/renew", nil, true); r.StatusCode != http.StatusNoContent {
		t.Errorf("renew = %d", r.StatusCode)
	}
	before, _ := enrollment.LoadState(agent.StateDir)
	if r := post("/rotate", nil, true); r.StatusCode != http.StatusNoContent {
		t.Errorf("rotate = %d", r.StatusCode)
	}
	if after, _ := enrollment.LoadState(agent.StateDir); after.Fingerprint == before.Fingerprint {
		t.Error("rotate did not change the key")
	}
	if r := post("/unenroll", nil, true); r.StatusCode != http.StatusNoContent {
		t.Errorf("unenroll = %d", r.StatusCode)
	}
	if v := status(); v["Enrolled"] != false {
		t.Errorf("still enrolled: %v", v)
	}
}
