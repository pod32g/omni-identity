package web

import (
	"sync"
	"time"
)

// Login rate-limit tuning: at most loginMaxAttempts failed attempts per
// loginWindow per (client IP + username) key.
const (
	loginMaxAttempts = 5
	loginWindow      = 15 * time.Minute
)

// rateLimiter is a fixed-window counter keyed by an arbitrary string. It is
// purpose-built for throttling failed login attempts: failures call Fail, a
// successful login calls Reset, and Allowed reports whether the key is still
// under its budget. The map is bounded by periodic sweeping of expired windows.
type rateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*window
	max      int
	ttl      time.Duration
	lastReap time.Time
	now      func() time.Time // injectable for tests
}

type window struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(max int, ttl time.Duration) *rateLimiter {
	return &rateLimiter{
		windows: make(map[string]*window),
		max:     max,
		ttl:     ttl,
		now:     time.Now,
	}
}

// Allowed reports whether another attempt is permitted for key.
func (rl *rateLimiter) Allowed(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	rl.reap(now)
	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		return true
	}
	return w.count < rl.max
}

// Fail records a failed attempt for key, starting a fresh window when needed.
func (rl *rateLimiter) Fail(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	rl.reap(now)
	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		rl.windows[key] = &window{count: 1, resetAt: now.Add(rl.ttl)}
		return
	}
	w.count++
}

// Reset clears the counter for key (called after a successful login).
func (rl *rateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.windows, key)
}

// reap drops expired windows, at most once per ttl, to bound memory. Caller
// holds the lock.
func (rl *rateLimiter) reap(now time.Time) {
	if now.Sub(rl.lastReap) < rl.ttl {
		return
	}
	rl.lastReap = now
	for k, w := range rl.windows {
		if now.After(w.resetAt) {
			delete(rl.windows, k)
		}
	}
}
