package enrollment_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
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

// The desktop launcher exits by itself once the page is no longer used, so a
// closed tab never leaves a root process behind.
func TestGUIExitsWhenIdle(t *testing.T) {
	agent := &enrollment.Agent{StateDir: filepath.Join(t.TempDir(), "s"), RuntimeDir: filepath.Join(t.TempDir(), "r"), Out: io.Discard}
	gui, err := enrollment.NewGUI(agent, enrollment.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gui.IdleTimeout = 300 * time.Millisecond
	launch, err := gui.Serve(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(launch); err != nil {
		t.Fatalf("first visit: %v", err)
	}
	select {
	case <-gui.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("GUI kept running after the idle timeout")
	}
	if _, err := http.Get(launch); err == nil {
		t.Error("server still answering after Done")
	}
}

// The launcher, polkit policy, and agent must agree on the binary path and
// the idle flag, or double-clicking the icon does nothing visible.
func TestDesktopLauncherFilesAgree(t *testing.T) {
	dir := filepath.Join("..", "..", "endpoint", "desktop")
	policyRaw, err := os.ReadFile(filepath.Join(dir, "com.omni-identity.enrollment.policy"))
	if err != nil {
		t.Skip("endpoint/desktop not present:", err)
	}
	var policy struct {
		Actions []struct {
			ID        string `xml:"id,attr"`
			Annotates []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"annotate"`
		} `xml:"action"`
	}
	if err := xml.Unmarshal(policyRaw, &policy); err != nil || len(policy.Actions) != 1 {
		t.Fatalf("policy: %v (%d actions)", err, len(policy.Actions))
	}
	execPath := ""
	for _, a := range policy.Actions[0].Annotates {
		if a.Key == "org.freedesktop.policykit.exec.path" {
			execPath = a.Value
		}
	}
	desktop, err := os.ReadFile(filepath.Join(dir, "omni-enrollment.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	want := "Exec=pkexec " + execPath + " --exit-when-idle "
	if execPath == "" || !strings.Contains(string(desktop), want) {
		t.Errorf("launcher Exec must start with %q:\n%s", want, desktop)
	}
	for _, line := range []string{"Terminal=false", "Icon=omni-enrollment", "Type=Application"} {
		if !strings.Contains(string(desktop), line+"\n") {
			t.Errorf("launcher missing %q", line)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "omni-enrollment.svg")); err != nil {
		t.Error("icon missing:", err)
	}
}
