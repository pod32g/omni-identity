package web

import "testing"

func TestSafeNext(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/dashboard", "/dashboard"},
		{"/admin/clients?x=1", "/admin/clients?x=1"},
		{"//evil.com", ""},          // protocol-relative
		{"https://evil.com", ""},    // absolute
		{"/\\evil.com", ""},         // backslash bypass (browsers normalize \ to /)
		{"\\\\evil.com", ""},        // leading backslashes
		{"/\tevil", ""},             // control char
		{"/path\nthing", ""},        // newline
		{"relative", ""},            // not rooted
		{"javascript:alert(1)", ""}, // scheme
	}
	for _, c := range cases {
		if got := safeNext(c.in); got != c.want {
			t.Errorf("safeNext(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
