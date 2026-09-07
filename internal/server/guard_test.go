package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("served")) })
}

func TestMockExposureGuardStopsTheProcessWhenProxied(t *testing.T) {
	// A forwarding header in mock mode means something in front of the broker is
	// carrying requests to it from elsewhere — which is exactly the situation the
	// loopback bind check was meant to prevent. Do not degrade, do not warn.
	for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		exposed := false
		h := MockExposureGuard(okHandler(), true, func() { exposed = true })

		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Header.Set(header, "203.0.113.7")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if !exposed {
			t.Errorf("%s did not trip the guard", header)
		}
		if w.Body.String() == "served" {
			t.Errorf("%s: the request was served anyway", header)
		}
	}
}

func TestMockExposureGuardPassesCleanRequests(t *testing.T) {
	exposed := false
	h := MockExposureGuard(okHandler(), true, func() { exposed = true })

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth", nil))

	if exposed {
		t.Error("the guard tripped on a request with no forwarding headers")
	}
	if w.Body.String() != "served" {
		t.Errorf("body = %q, want the request to be served", w.Body.String())
	}
}

func TestExposureGuardIsInertInTelegramMode(t *testing.T) {
	// Behind Traefik these headers are normal and correct.
	exposed := false
	h := MockExposureGuard(okHandler(), false, func() { exposed = true })

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if exposed {
		t.Error("the guard tripped in telegram mode, where the proxy is expected")
	}
	if w.Body.String() != "served" {
		t.Error("the request was not served")
	}
}

func TestRateLimiterAllowsABurstThenRefuses(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(3, time.Minute, func() time.Time { return now })

	for i := range 3 {
		if !rl.Allow("203.0.113.7") {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	if rl.Allow("203.0.113.7") {
		t.Error("the limiter let a fourth request through in the same window")
	}
	// A different address has its own budget.
	if !rl.Allow("198.51.100.4") {
		t.Error("one address exhausted another address's budget")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(1, time.Minute, func() time.Time { return now })

	if !rl.Allow("203.0.113.7") || rl.Allow("203.0.113.7") {
		t.Fatal("the limiter did not start with exactly one token")
	}
	now = now.Add(time.Minute)
	if !rl.Allow("203.0.113.7") {
		t.Error("the budget did not come back after the window")
	}
}

func TestRateLimiterForgetsIdleAddresses(t *testing.T) {
	// Without this the map is an unbounded allocation driven by whoever sends the
	// most distinct source addresses.
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(5, time.Minute, func() time.Time { return now })
	rl.Allow("203.0.113.7")

	now = now.Add(time.Hour)
	if removed := rl.Sweep(); removed != 1 {
		t.Errorf("Sweep() removed %d idle addresses, want 1", removed)
	}
}
