package sieg

import (
	"testing"
	"time"
)

func TestRateLimiter_BurstThenThrottle(t *testing.T) {
	r := newRateLimiter(10, 5) // 10/s, burst 5

	// Burst of 5 must succeed.
	for i := 0; i < 5; i++ {
		if !r.allow("1.2.3.4") {
			t.Errorf("burst attempt %d: should be allowed", i+1)
		}
	}
	// 6th in the same instant should be denied.
	if r.allow("1.2.3.4") {
		t.Error("after burst, request should be throttled")
	}
}

func TestRateLimiter_PerKeyIsolation(t *testing.T) {
	r := newRateLimiter(10, 3)
	for i := 0; i < 3; i++ {
		if !r.allow("a") {
			t.Fatalf("a #%d should be allowed", i+1)
		}
	}
	if r.allow("a") {
		t.Error("a is exhausted, should be throttled")
	}
	// Different key has its own bucket.
	if !r.allow("b") {
		t.Error("b's first request should be allowed")
	}
}

func TestRateLimiter_Refills(t *testing.T) {
	r := newRateLimiter(100, 1) // 100/s, burst 1
	if !r.allow("k") {
		t.Fatal("first should pass")
	}
	if r.allow("k") {
		t.Fatal("second should be denied immediately")
	}
	// Wait long enough for one token to refill.
	time.Sleep(15 * time.Millisecond)
	if !r.allow("k") {
		t.Error("after sleep, should refill at least one token")
	}
}

func TestRateLimiter_DisabledWhenZero(t *testing.T) {
	r := newRateLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if !r.allow("anything") {
			t.Errorf("nil limiter should always allow (i=%d)", i)
		}
	}
}
