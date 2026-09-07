//go:build !windows

package enrollment

// privilegedUID says whether the broker must refuse a caller: root and
// system accounts never get user tokens, and a peer without a resolvable
// uid (-1) is refused too.
func privilegedUID(uid int) bool { return uid <= 0 }
