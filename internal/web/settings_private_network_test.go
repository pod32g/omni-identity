package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The private-network HTTP redirect policy is off by default, editable live,
// and only admits hosts that cannot be reached from the public Internet.
func TestSettingsLiveAppliesPrivateNetworkRedirectPolicy(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)

	if srv.settings.Current().AllowPrivateNetworkHTTPRedirect {
		t.Fatal("private-network HTTP redirects should be off by default")
	}
	body := adminGet(srv, "/admin/settings", sid).Body.String()
	if !strings.Contains(body, `name="allow_private_network_http_redirects"`) {
		t.Fatal("settings page is missing the private-network toggle")
	}

	create := func(id, uri string) int {
		return adminPost(srv, "/admin/clients", url.Values{
			"name":          {"Homelab app"},
			"client_id":     {id},
			"type":          {"public"},
			"redirect_uris": {uri},
			"scopes":        {"openid"},
		}, sid).Code
	}

	// Off: a LAN http:// callback is refused, and the error does not advertise
	// the private-network option.
	rr := adminPost(srv, "/admin/clients", url.Values{
		"name": {"Homelab app"}, "client_id": {"lan-off"}, "type": {"public"},
		"redirect_uris": {"http://192.168.68.34:3002/auth/callback"}, "scopes": {"openid"},
	}, sid)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("policy off: code = %d, want 400", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "private network") {
		t.Error("policy off: error message should not mention the private-network option")
	}

	// On: private IPs and reserved local names are accepted, public hosts are not.
	applySettings(t, srv, func(sv *SettingsView) { sv.AllowPrivateNetworkHTTPRedirect = true })
	if code := create("lan-ip", "http://192.168.68.34:3002/auth/callback"); code != http.StatusOK {
		t.Errorf("policy on, private IP: code = %d, want 200", code)
	}
	if code := create("lan-name", "http://bugtracker.omni.home.arpa:3002/auth/callback"); code != http.StatusOK {
		t.Errorf("policy on, home.arpa name: code = %d, want 200", code)
	}
	if code := create("lan-public", "http://app.example.com/auth/callback"); code != http.StatusBadRequest {
		t.Errorf("policy on, public host: code = %d, want 400", code)
	}

	// Back off: the same LAN URI is refused again, live.
	applySettings(t, srv, func(sv *SettingsView) { sv.AllowPrivateNetworkHTTPRedirect = false })
	if code := create("lan-off-again", "http://192.168.68.34:3002/auth/callback"); code != http.StatusBadRequest {
		t.Errorf("policy off again: code = %d, want 400", code)
	}
}
