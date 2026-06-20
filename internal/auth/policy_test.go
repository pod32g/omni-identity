package auth

import "testing"

func TestValidatePasswordPolicy(t *testing.T) {
	full := PasswordPolicy{MinLength: 10, RequireUpper: true, RequireLower: true, RequireNumber: true, RequireSymbol: true}
	cases := []struct {
		name   string
		pw     string
		policy PasswordPolicy
		ok     bool
	}{
		{"too short", "Aa1!", full, false},
		{"missing upper", "abcdefg1!x", full, false},
		{"missing lower", "ABCDEFG1!X", full, false},
		{"missing number", "Abcdefgh!x", full, false},
		{"missing symbol", "Abcdefgh1x", full, false},
		{"meets all", "Abcdefg1!x", full, true},
		{"number only policy ok", "abcdefghij1", PasswordPolicy{MinLength: 10, RequireNumber: true}, true},
		{"number only policy fail", "abcdefghijk", PasswordPolicy{MinLength: 10, RequireNumber: true}, false},
		{"min length floor 8", "Ab1!xy", PasswordPolicy{MinLength: 4}, false}, // floored to 8
	}
	for _, c := range cases {
		msg := ValidatePassword(c.pw, "", "", c.policy)
		if (msg == "") != c.ok {
			t.Errorf("%s: ValidatePassword(%q) = %q, want ok=%v", c.name, c.pw, msg, c.ok)
		}
	}
}

func TestValidatePasswordRejectsIdentityMatch(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, RequireNumber: true}
	if ValidatePassword("alice1234", "alice1234", "", p) == "" {
		t.Error("password equal to username should be rejected")
	}
	if ValidatePassword("alice@x.com1", "", "alice@x.com1", p) == "" {
		t.Error("password equal to email should be rejected")
	}
}
