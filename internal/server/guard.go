package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// forwardingHeaders are the marks a reverse proxy leaves. In mock mode their
// presence means requests are reaching the broker from somewhere other than this
// machine, which is the situation the loopback bind check exists to prevent.
var forwardingHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	"X-Forwarded-Port", "X-Real-IP", "Forwarded",
}

// MockExposureGuard refuses the request and calls onExposed — which is wired to
// shutting the process down — the first time a mock-mode request arrives through
// a proxy.
//
// Mock reachable from outside is a "choose an identity" page on the internet:
// PKCE and state both check out, the allow list cannot help because mock users
// carry real ids, and one click is a full account takeover. So the answer is to
// stop, not to warn and carry on.
func MockExposureGuard(next http.Handler, mockEnabled bool, onExposed func()) http.Handler {
	if !mockEnabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range forwardingHeaders {
			if r.Header.Get(h) != "" {
				http.Error(w, "mock mode is not reachable through a proxy", http.StatusMisdirectedRequest)
				onExposed()
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimiter is layer 5: a fixed budget per source address per window. It is
// deliberately the simplest thing that bounds both request rate and the memory a
// stranger can make the broker allocate.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration
	now     func() time.Time
}

type bucket struct {
	count int
	start time.Time
}

func NewRateLimiter(limit int, window time.Duration, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{buckets: map[string]*bucket{}, limit: limit, window: window, now: now}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok || now.Sub(b.start) >= rl.window {
		rl.buckets[key] = &bucket{count: 1, start: now}
		return true
	}
	if b.count >= rl.limit {
		return false
	}
	b.count++
	return true
}

// Sweep drops addresses whose window is long past, so the map stays bounded by
// recent traffic rather than by total traffic.
func (rl *RateLimiter) Sweep() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	removed := 0
	for key, b := range rl.buckets {
		if now.Sub(b.start) >= rl.window {
			delete(rl.buckets, key)
			removed++
		}
	}
	return removed
}

// Middleware applies the limit to everything below it. The key is the peer
// address: in telegram mode X-Forwarded-For is present and trustworthy only
// because Traefik sets it, but trusting a header for rate limiting would let a
// caller mint a fresh budget per request.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !rl.Allow(host) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
