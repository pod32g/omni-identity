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

// ValidatePassword enforces the password policy: a minimum length, at least one
// letter and one digit, and not trivially equal to the username or email. It
// returns a user-facing error message string, or "" if the password is allowed.
func ValidatePassword(password, username, email string, minLen int) string {
	if minLen < 8 {
		minLen = 8
	}
	if len(password) < minLen {
		return fmt.Sprintf("Password must be at least %d characters.", minLen)
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return "Password must contain both letters and numbers."
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
