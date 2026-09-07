// Package store holds the two short-lived tables of the login flow: the pending
// authorizations waiting for Telegram to send the browser back, and the codes
// waiting to be exchanged for a token.
//
// Both are deliberately in memory. Losing them on restart costs a login in
// flight, which the user retries; the registry, not this, is what has to survive.
package store

import (
	"sync"
	"time"

	"github.com/proshik/telegram-login-broker/internal/oidc"
)

// PendingAuth is an authorization that has been started and sent upstream. It is
// keyed by the state the broker generated for Telegram, not by the state the
// application sent.
type PendingAuth struct {
	ClientID      string
	RedirectURI   string
	State         string // the application's state, echoed back untouched
	CodeChallenge string
	// Browser is the value of the __Host- cookie set on /auth. Matching it on
	// /callback is what distinguishes "the same browser came back" from "an
	// attacker finished a login and handed over the link".
	Browser string
	// UpstreamVerifier is the broker's own PKCE verifier for its exchange with
	// Telegram. It is unrelated to the application's code_challenge above: the
	// broker is a client of Telegram and a provider to the application, and the
	// two PKCE pairs must not be confused.
	UpstreamVerifier string
}

// IssuedCode is an authorization code waiting on /token.
type IssuedCode struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Identity      oidc.Identity
}

type entry[T any] struct {
	value   T
	expires time.Time
}

// Store is one mutex over two maps. It is not sharded and does not use RWMutex:
// the hot operations are Take*, which are writes, and the load is a handful of
// logins per hour.
type Store struct {
	mu      sync.Mutex
	pending map[string]entry[PendingAuth]
	codes   map[string]entry[IssuedCode]

	now        func() time.Time
	pendingTTL time.Duration
	codeTTL    time.Duration
}

func New(now func() time.Time, pendingTTL, codeTTL time.Duration) *Store {
	return &Store{
		pending:    make(map[string]entry[PendingAuth]),
		codes:      make(map[string]entry[IssuedCode]),
		now:        now,
		pendingTTL: pendingTTL,
		codeTTL:    codeTTL,
	}
}

func (s *Store) PutPending(key string, p PendingAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[key] = entry[PendingAuth]{value: p, expires: s.now().Add(s.pendingTTL)}
}

// TakePending removes the entry and returns it. A miss and an expiry are the
// same answer on purpose: the caller has nothing different to do about them.
func (s *Store) TakePending(key string) (PendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return take(s, s.pending, key)
}

func (s *Store) PutCode(code string, c IssuedCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = entry[IssuedCode]{value: c, expires: s.now().Add(s.codeTTL)}
}

// TakeCode removes the code under the same lock that reads it, before the caller
// has validated anything. Replay is therefore structurally impossible rather
// than merely checked for, and a wrong code_verifier burns the code — which is
// what OAuth 2.1 asks for.
func (s *Store) TakeCode(code string) (IssuedCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return take(s, s.codes, code)
}

func take[T any](s *Store, m map[string]entry[T], key string) (T, bool) {
	var zero T
	e, ok := m[key]
	if !ok {
		return zero, false
	}
	delete(m, key)
	// Expiry is decided here, on the read, so correctness never depends on how
	// recently the janitor ran.
	if !s.now().Before(e.expires) {
		return zero, false
	}
	return e.value, true
}

// Sweep drops expired entries and reports how many it removed. It exists only to
// return memory; nothing about the flow's correctness depends on it running.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for k, e := range s.pending {
		if !now.Before(e.expires) {
			delete(s.pending, k)
			removed++
		}
	}
	for k, e := range s.codes {
		if !now.Before(e.expires) {
			delete(s.codes, k)
			removed++
		}
	}
	return removed
}
