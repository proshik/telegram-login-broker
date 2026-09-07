package store

import (
	"sync"
	"testing"
	"time"

	"github.com/proshik/telegram-login-broker/internal/oidc"
)

// fakeClock keeps every expiry test off the wall clock: no test in this package
// may sleep.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore(clk *fakeClock) *Store {
	return New(clk.Now, 5*time.Minute, 60*time.Second)
}

func samplePending() PendingAuth {
	return PendingAuth{
		ClientID:      "kotlin-app",
		RedirectURI:   "http://localhost:8080/auth/telegram/callback",
		State:         "app-state",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Browser:       "browser-binding",
	}
}

func sampleCode() IssuedCode {
	return IssuedCode{
		ClientID:      "kotlin-app",
		RedirectURI:   "http://localhost:8080/auth/telegram/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Identity:      oidc.Identity{ID: 123456789, Name: "Пётр"},
	}
}

func TestTakePendingReturnsStoredValue(t *testing.T) {
	s := newTestStore(newFakeClock())
	s.PutPending("upstream-state", samplePending())

	got, ok := s.TakePending("upstream-state")
	if !ok {
		t.Fatal("TakePending() missed a value that was just stored")
	}
	if got.ClientID != "kotlin-app" || got.State != "app-state" {
		t.Errorf("TakePending() = %+v, want the stored pending auth", got)
	}
}

func TestTakePendingConsumesTheEntry(t *testing.T) {
	s := newTestStore(newFakeClock())
	s.PutPending("upstream-state", samplePending())
	s.TakePending("upstream-state")

	if _, ok := s.TakePending("upstream-state"); ok {
		t.Error("TakePending() returned the same pending auth twice")
	}
}

func TestTakeCodeConsumesTheCodeSoReplayFails(t *testing.T) {
	s := newTestStore(newFakeClock())
	s.PutCode("the-code", sampleCode())

	if _, ok := s.TakeCode("the-code"); !ok {
		t.Fatal("TakeCode() missed a code that was just issued")
	}
	// The second attempt is the replay: the code is gone regardless of what the
	// caller decided about the first one.
	if _, ok := s.TakeCode("the-code"); ok {
		t.Error("TakeCode() returned the same code twice")
	}
}

func TestExpiryIsCheckedOnReadWithoutSweep(t *testing.T) {
	clk := newFakeClock()
	s := newTestStore(clk)
	s.PutPending("upstream-state", samplePending())
	s.PutCode("the-code", sampleCode())

	clk.Advance(61 * time.Second)
	if _, ok := s.TakeCode("the-code"); ok {
		t.Error("TakeCode() returned a code past its 60s TTL")
	}
	// The pending auth has a longer life and must still be there.
	if _, ok := s.TakePending("upstream-state"); !ok {
		t.Error("TakePending() dropped an entry that is still inside its TTL")
	}

	s.PutPending("second", samplePending())
	clk.Advance(5*time.Minute + time.Second)
	if _, ok := s.TakePending("second"); ok {
		t.Error("TakePending() returned an entry past its 5m TTL")
	}
}

func TestSweepOnlyFreesMemory(t *testing.T) {
	clk := newFakeClock()
	s := newTestStore(clk)
	s.PutPending("live", samplePending())
	s.PutCode("dead", sampleCode())

	clk.Advance(61 * time.Second)
	if removed := s.Sweep(); removed != 1 {
		t.Errorf("Sweep() removed %d entries, want 1 (the expired code)", removed)
	}
	if _, ok := s.TakePending("live"); !ok {
		t.Error("Sweep() dropped a live entry")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	s := newTestStore(newFakeClock())
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := string(rune('a' + i%26))
			s.PutCode(key, sampleCode())
			s.TakeCode(key)
			s.PutPending(key, samplePending())
			s.TakePending(key)
			s.Sweep()
		}()
	}
	wg.Wait()
}
