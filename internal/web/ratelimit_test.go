package web

import (
	"testing"
	"time"
)

func TestRateLimiterBlocksAfterMax(t *testing.T) {
	rl := newRateLimiter()
	key := "1.2.3.4|alice"

	for i := 0; i < 3; i++ {
		if !rl.Allowed(key, 3, time.Minute) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
		rl.Fail(key, time.Minute)
	}
	if rl.Allowed(key, 3, time.Minute) {
		t.Error("4th attempt should be blocked")
	}
}

func TestRateLimiterResetClearsWindow(t *testing.T) {
	rl := newRateLimiter()
	key := "k"
	rl.Fail(key, time.Minute)
	rl.Fail(key, time.Minute)
	if rl.Allowed(key, 2, time.Minute) {
		t.Fatal("should be blocked after 2 fails")
	}
	rl.Reset(key)
	if !rl.Allowed(key, 2, time.Minute) {
		t.Error("Reset should clear the window")
	}
}

func TestRateLimiterWindowExpires(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	rl := newRateLimiter()
	rl.now = func() time.Time { return now }

	rl.Fail("k", time.Minute)
	if rl.Allowed("k", 1, time.Minute) {
		t.Fatal("blocked within the window")
	}
	// Advance past the window.
	now = now.Add(2 * time.Minute)
	if !rl.Allowed("k", 1, time.Minute) {
		t.Error("window should have expired")
	}
}
