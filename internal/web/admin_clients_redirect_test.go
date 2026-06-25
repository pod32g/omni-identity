package web

import "testing"

func TestHTTPSOrLocalURLs_PrivateScheme(t *testing.T) {
	cases := []struct {
		name               string
		uris               []string
		allowLoopbackHTTP  bool
		allowPrivateScheme bool
		want               bool
	}{
		{"https ok", []string{"https://app.example.com/cb"}, false, false, true},
		{"http rejected", []string{"http://app.example.com/cb"}, false, false, false},
		{"loopback http allowed", []string{"http://127.0.0.1:7777/cb"}, true, false, true},
		{"loopback http disallowed", []string{"http://127.0.0.1:7777/cb"}, false, false, false},
		{"custom scheme with host allowed for public", []string{"com.omnivideo.app://oauth/callback"}, false, true, true},
		{"custom scheme path-only allowed for public", []string{"com.omnivideo.app:/oauth/callback"}, false, true, true},
		{"custom scheme rejected when not public", []string{"com.omnivideo.app://oauth/callback"}, false, false, false},
		{"non-reverse-dns scheme rejected", []string{"myapp://callback"}, false, true, false},
		{"wildcard rejected even for public", []string{"com.omnivideo.app://*"}, false, true, false},
		{"fragment rejected", []string{"https://app.example.com/cb#x"}, false, true, false},
		{"mixed valid+invalid", []string{"https://ok.example.com/cb", "http://evil.example.com/cb"}, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpsOrLocalURLs(tc.uris, tc.allowLoopbackHTTP, tc.allowPrivateScheme); got != tc.want {
				t.Fatalf("httpsOrLocalURLs(%v, loopback=%v, private=%v) = %v, want %v",
					tc.uris, tc.allowLoopbackHTTP, tc.allowPrivateScheme, got, tc.want)
			}
		})
	}
}

func TestIsPrivateUseScheme(t *testing.T) {
	valid := []string{"com.omnivideo.app", "io.omni.video", "COM.Example.App"}
	for _, s := range valid {
		if !isPrivateUseScheme(s) {
			t.Errorf("isPrivateUseScheme(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "http", "https", "myapp", "customscheme"}
	for _, s := range invalid {
		if isPrivateUseScheme(s) {
			t.Errorf("isPrivateUseScheme(%q) = true, want false", s)
		}
	}
}
