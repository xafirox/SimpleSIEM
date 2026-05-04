package sieg

import (
	"sync"
	"time"
)

// rateLimiter is a per-key token-bucket: each key (we use the remote IP)
// gets `burst` tokens and refills at `rate` tokens per second. allow()
// returns true when a token is available and consumes it; otherwise
// false. Old buckets are pruned periodically so memory can't grow under
// a churn of unique IPs.
//
// The implementation is intentionally minimal — a real production
// gateway would use github.com/uber-go/ratelimit or similar — but it's
// enough to defeat trivial flooding without an extra dependency.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // max tokens
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perSec, burst int) *rateLimiter {
	if perSec <= 0 || burst <= 0 {
		return nil // disabled
	}
	return &rateLimiter{
		rate:    float64(perSec),
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		lastGC:  time.Now(),
	}
}

// allow consumes one token for key. Returns true if the request can
// proceed. A nil receiver means "rate limiting disabled" — always allow.
func (r *rateLimiter) allow(key string) bool {
	if r == nil {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if now.Sub(r.lastGC) > time.Minute {
		r.gc(now)
		r.lastGC = now
	}

	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[key] = b
	}
	// Refill since last touch.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops buckets that haven't been touched in 5 minutes so a
// short-lived flood from many unique IPs doesn't grow the map without
// bound. Called inline under the mutex; cheap because the map is small.
func (r *rateLimiter) gc(now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	for k, b := range r.buckets {
		if b.last.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}
