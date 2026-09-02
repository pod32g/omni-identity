package web

import "testing"

func TestIsPrivateNetworkHost(t *testing.T) {
	private := []string{
		"192.168.68.34", "10.0.0.5", "172.16.4.9", "172.31.255.1", // RFC 1918
		"100.64.0.1", "100.101.214.34", "100.127.255.254", // CGNAT / Tailscale
		"169.254.10.10", "fe80::1", "fd12:3456::1", "FC00::1", // link-local, ULA
		"chizu", "omni", // single-label
		"bugtracker.omni.home.arpa", "app.internal", "printer.local", "nas.lan", "box.home", "srv.corp", "pc.localdomain",
		"App.Home.Arpa.", "  chizu  ",
	}
	for _, h := range private {
		if !isPrivateNetworkHost(h) {
			t.Errorf("isPrivateNetworkHost(%q) = false, want true", h)
		}
	}
	public := []string{
		"", "8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.1", "192.169.0.1", "2001:db8::1",
		"127.0.0.1", "::1", "localhost", // loopback is the other policy's job
		"0.0.0.0", "224.0.0.1",
		"example.com", "app.example.com", "evil.home.arpa.example.com", "home.arpa.attacker.net",
		"internal.example.com", "local.example.com",
	}
	for _, h := range public {
		if isPrivateNetworkHost(h) {
			t.Errorf("isPrivateNetworkHost(%q) = true, want false", h)
		}
	}
}

func TestHTTPSOrLocalURLs_PrivateNetwork(t *testing.T) {
	cases := []struct {
		name                string
		uris                []string
		allowPrivateNetwork bool
		want                bool
	}{
		{"private ip allowed", []string{"http://192.168.68.34:3002/auth/callback"}, true, true},
		{"private ip rejected when off", []string{"http://192.168.68.34:3002/auth/callback"}, false, false},
		{"home.arpa name allowed", []string{"http://bugtracker.omni.home.arpa:3002/auth/callback"}, true, true},
		{"internal name allowed", []string{"http://app.internal/cb"}, true, true},
		{"single-label host allowed", []string{"http://chizu:3002/cb"}, true, true},
		{"tailscale ip allowed", []string{"http://100.101.214.34:3002/cb"}, true, true},
		{"public host still rejected", []string{"http://app.example.com/cb"}, true, false},
		{"public ip still rejected", []string{"http://8.8.8.8/cb"}, true, false},
		{"lookalike suffix rejected", []string{"http://x.home.arpa.example.com/cb"}, true, false},
		{"loopback not covered by this flag", []string{"http://127.0.0.1:7777/cb"}, true, false},
		{"credentials rejected", []string{"http://user:pw@192.168.1.2/cb"}, true, false},
		{"fragment rejected", []string{"http://192.168.1.2/cb#x"}, true, false},
		{"wildcard rejected", []string{"http://192.168.1.*/cb"}, true, false},
		{"https unaffected", []string{"https://app.example.com/cb"}, false, true},
		{"mixed private + public rejected", []string{"http://192.168.1.2/cb", "http://app.example.com/cb"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpsOrLocalURLs(tc.uris, false, tc.allowPrivateNetwork, false); got != tc.want {
				t.Fatalf("httpsOrLocalURLs(%v, privateNetwork=%v) = %v, want %v", tc.uris, tc.allowPrivateNetwork, got, tc.want)
			}
		})
	}
}

func TestRedirectURIMessage_PrivateNetwork(t *testing.T) {
	msg := redirectURIMessage("Redirect", true, true, false)
	for _, want := range []string{"must use HTTPS", "loopback", "private network"} {
		if !contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	if contains(redirectURIMessage("Redirect", true, false, false), "private network") {
		t.Error("private-network hint shown while the policy is off")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
