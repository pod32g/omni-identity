package oidc

import (
	"slices"
	"strings"
)

// SupportedScopes are all scopes Omni Identity recognizes.
var SupportedScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess}

// SplitScope splits a space-delimited scope string into its components.
func SplitScope(scope string) []string {
	return strings.Fields(scope)
}

// HasScope reports whether scope contains want.
func HasScope(scope, want string) bool {
	return slices.Contains(SplitScope(scope), want)
}

// ScopesSubset reports whether every requested scope is in allowed.
func ScopesSubset(requested, allowed []string) bool {
	for _, r := range requested {
		if !slices.Contains(allowed, r) {
			return false
		}
	}
	return true
}
