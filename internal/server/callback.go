package server

import (
	"crypto/subtle"
	"net/http"
	"strconv"

	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/store"
)

// takeFlow consumes the pending authorization and checks that the browser
// finishing the login is the one that started it.
//
// Upstream state alone cannot tell "the same browser came back" from "an
// attacker completed a login and handed over the link", which is login-CSRF:
// the victim ends up signed in as the attacker. The binding cookie is what
// separates the two.
func (s *Server) takeFlow(w http.ResponseWriter, r *http.Request, flow string) (store.PendingAuth, bool) {
	pending, ok := s.opts.Store.TakePending(flow)
	if !ok {
		s.refuse(w, r, http.StatusBadRequest, "this login has expired or was already completed")
		return store.PendingAuth{}, false
	}
	cookie, err := r.Cookie(bindingCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(pending.Browser)) != 1 {
		s.opts.Logger.Warn("browser binding mismatch", "client_id", pending.ClientID)
		s.refuse(w, r, http.StatusBadRequest, "this login was started in a different browser")
		return store.PendingAuth{}, false
	}
	return pending, true
}

// handleSelect is the mock mode's stand-in for Telegram: the identity comes from
// a list instead of from a login. It exists only when mock is on, and mock only
// starts on loopback.
func (s *Server) handleSelect(w http.ResponseWriter, r *http.Request) {
	if !s.opts.Config.MockEnabled {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		s.refuse(w, r, http.StatusBadRequest, "malformed form")
		return
	}

	pending, ok := s.takeFlow(w, r, r.PostForm.Get("flow"))
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "no such mock user")
		return
	}
	for _, u := range s.opts.Config.MockUsers {
		if u.ID == id {
			s.finish(w, r, pending, oidc.Identity{
				ID: u.ID, Name: u.Name, Username: u.Username, PhotoURL: u.PhotoURL,
			})
			return
		}
	}
	s.refuse(w, r, http.StatusBadRequest, "no such mock user")
}

// handleCallback is where Telegram returns the browser. The address is fixed and
// registered in BotFather once per bot; which application the login belongs to
// is decided here, from the flow, not by Telegram.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.opts.Config.MockEnabled {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if desc := q.Get("error"); desc != "" {
		s.opts.Logger.Warn("upstream refused the login", "error", desc)
		s.refuse(w, r, http.StatusBadRequest, "Telegram refused the login")
		return
	}

	pending, ok := s.takeFlow(w, r, q.Get("state"))
	if !ok {
		return
	}
	code := q.Get("code")
	if code == "" {
		s.refuse(w, r, http.StatusBadRequest, "Telegram returned no code")
		return
	}

	_, bot, err := s.opts.Registry.ResolveClient(pending.ClientID)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "the client behind this login is no longer registered")
		return
	}
	identity, err := s.opts.Upstream.Exchange(r.Context(), bot, code, pending.UpstreamVerifier, s.callbackURL())
	if err != nil {
		s.opts.Logger.Error("upstream exchange failed", "client_id", pending.ClientID, "err", err)
		s.refuse(w, r, http.StatusBadGateway, "could not complete the login with Telegram")
		return
	}
	s.finish(w, r, pending, identity)
}
