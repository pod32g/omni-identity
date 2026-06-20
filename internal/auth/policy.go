package auth

import (
	"fmt"
	"strings"
	"unicode"
)

// DummyVerify runs a password verification against a fixed dummy hash to keep
// authentication timing roughly constant when the target account does not exist
// or is skipped, mitigating username enumeration.
func DummyVerify(password string) {
	_, _ = VerifyPassword(password, dummyHash)
}

// PasswordPolicy is the configurable password-strength policy.
type PasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSymbol bool
}

// Describe returns a human-readable summary of the policy for UI hints.
func (p PasswordPolicy) Describe() string {
	min := p.MinLength
	if min < 8 {
		min = 8
	}
	parts := []string{fmt.Sprintf("at least %d characters", min)}
	if p.RequireUpper {
		parts = append(parts, "an uppercase letter")
	}
	if p.RequireLower {
		parts = append(parts, "a lowercase letter")
	}
	if p.RequireNumber {
		parts = append(parts, "a number")
	}
	if p.RequireSymbol {
		parts = append(parts, "a symbol")
	}
	return strings.Join(parts, ", ")
}

// ValidatePassword enforces the policy: a minimum length, the required character
// classes, and not trivially equal to the username or email. It returns a
// user-facing error message string, or "" if the password is allowed.
func ValidatePassword(password, username, email string, p PasswordPolicy) string {
	minLen := p.MinLength
	if minLen < 8 {
		minLen = 8
	}
	if len([]rune(password)) < minLen {
		return fmt.Sprintf("Password must be at least %d characters.", minLen)
	}

	var hasUpper, hasLower, hasNumber, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	switch {
	case p.RequireUpper && !hasUpper:
		return "Password must contain an uppercase letter."
	case p.RequireLower && !hasLower:
		return "Password must contain a lowercase letter."
	case p.RequireNumber && !hasNumber:
		return "Password must contain a number."
	case p.RequireSymbol && !hasSymbol:
		return "Password must contain a symbol."
	}

	lower := strings.ToLower(password)
	if username != "" && lower == strings.ToLower(username) {
		return "Password must not match your username."
	}
	if email != "" && lower == strings.ToLower(email) {
		return "Password must not match your email."
	}
	return ""
}
