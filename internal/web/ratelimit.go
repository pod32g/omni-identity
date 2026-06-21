package web

import (
	"sync"
	"time"
)

// Login rate-limit tuning. The per-user key slows credential stuffing; the
// IP-only budget runs before password hashing so username rotation cannot force
// unbounded Argon2id work from one source.
const (
	defaultLoginMaxAttempts          = 5
	defaultLoginIPMaxAttempts        = 20
	defaultRateLimitWindow           = 15 * time.Minute
	defaultPasswordVerifyConcurrency = 4
	defaultMaxLoginUsernameBytes     = 320
	defaultMaxLoginPasswordBytes     = 1024
)

// rateLimiter is a fixed-window counter keyed by an arbitrary string. It is
// purpose-built for throttling failed login attempts: failures call Fail, a
// successful login calls Reset, and Allowed reports whether the key is still
// under its budget. The map is bounded by periodic sweeping of expired windows.
type rateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*window
	lastReap time.Time
	now      func() time.Time // injectable for tests
}

type window struct {
	count   int
	resetAt time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		windows: make(map[string]*window),
		now:     time.Now,
	}
}

// Allowed reports whether another attempt is permitted for key.
func (rl *rateLimiter) Allowed(key string, max int, ttl time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	max, ttl = normalizeLimit(max, ttl)
	now := rl.now()
	rl.reap(now, ttl)
	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		return true
	}
	return w.count < max
}

// Fail records a failed attempt for key, starting a fresh window when needed.
func (rl *rateLimiter) Fail(key string, ttl time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	_, ttl = normalizeLimit(1, ttl)
	now := rl.now()
	rl.reap(now, ttl)
	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		rl.windows[key] = &window{count: 1, resetAt: now.Add(ttl)}
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
func (rl *rateLimiter) reap(now time.Time, ttl time.Duration) {
	if now.Sub(rl.lastReap) < ttl {
		return
	}
	rl.lastReap = now
	for k, w := range rl.windows {
		if now.After(w.resetAt) {
			delete(rl.windows, k)
		}
	}
}

func normalizeLimit(max int, ttl time.Duration) (int, time.Duration) {
	if max < 1 {
		max = defaultLoginMaxAttempts
	}
	if ttl <= 0 {
		ttl = defaultRateLimitWindow
	}
	return max, ttl
}
