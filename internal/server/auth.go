package server

import (
	"net/http"
	"net/url"

	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/store"
)

// Field ceilings, applied before anything is written to the store. They are not
// about correctness of the protocol so much as about not letting a stranger
// decide how much memory a request costs.
const (
	maxState       = 512
	maxRedirectURI = 2048
	maxClientID    = 128
)

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")

	switch {
	case clientID == "" || len(clientID) > maxClientID:
		s.refuse(w, r, http.StatusBadRequest, "client_id is missing or too long")
		return
	case redirectURI == "" || len(redirectURI) > maxRedirectURI:
		s.refuse(w, r, http.StatusBadRequest, "redirect_uri is missing or too long")
		return
	case len(state) > maxState:
		s.refuse(w, r, http.StatusBadRequest, "state is too long")
		return
	case q.Get("response_type") != "code":
		s.refuse(w, r, http.StatusBadRequest, "only response_type=code is supported")
		return
	case q.Get("code_challenge_method") != "S256":
		s.refuse(w, r, http.StatusBadRequest, "only code_challenge_method=S256 is supported")
		return
	}
	if err := oidc.ValidateChallengeFormat(challenge); err != nil {
		s.refuse(w, r, http.StatusBadRequest, "code_challenge is not a valid S256 challenge")
		return
	}

	// Layer 1: an application nobody registered stops here, before the broker
	// acts on its behalf.
	client, bot, err := s.opts.Registry.ResolveClient(clientID)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "this client_id is not registered with the broker")
		return
	}
	// Layer 3. On failure the answer is a page of our own: never a redirect to an
	// address that just failed validation, not even to report the error.
	if err := CheckRedirectURI(redirectURI, client.RedirectOrigins); err != nil {
		s.opts.Logger.Warn("rejected redirect_uri", "client_id", clientID, "err", err)
		s.refuse(w, r, http.StatusBadRequest, "redirect_uri is neither a loopback address nor an allow-listed origin")
		return
	}

	flow, err := randomToken()
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "cannot start a login")
		return
	}
	binding, err := randomToken()
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "cannot start a login")
		return
	}
	upstreamVerifier, err := randomToken()
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "cannot start a login")
		return
	}

	s.opts.Store.PutPending(flow, store.PendingAuth{
		ClientID:         clientID,
		RedirectURI:      redirectURI,
		State:            state,
		CodeChallenge:    challenge,
		Browser:          binding,
		UpstreamVerifier: upstreamVerifier,
	})
	s.setBinding(w, binding)

	if s.opts.Config.MockEnabled {
		s.renderChooser(w, flow)
		return
	}
	http.Redirect(w, r,
		s.opts.Upstream.AuthURL(bot, s.callbackURL(), flow, oidc.S256Challenge(upstreamVerifier)),
		http.StatusFound)
}

// finish is the single exit both modes share once an identity is known: check
// the allow list, mint a code, and send the browser back to the application.
func (s *Server) finish(w http.ResponseWriter, r *http.Request, pending store.PendingAuth, identity oidc.Identity) {
	// Layer 4. A stranger gets all the way to here and is refused with a page of
	// ours, which is exactly what makes the refusal legible.
	if !s.opts.Config.IDAllowed(identity.ID) {
		s.opts.Logger.Warn("refused telegram id", "id", identity.ID, "client_id", pending.ClientID)
		s.renderRefused(w)
		return
	}

	code, err := randomToken()
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "cannot issue a code")
		return
	}
	s.opts.Store.PutCode(code, store.IssuedCode{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		Identity:      identity,
	})
	s.clearBinding(w)

	// Built through url.Values, never by concatenation: state is chosen by the
	// application and redirect_uri may already carry a query of its own.
	u, err := url.Parse(pending.RedirectURI)
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "cannot build the callback")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if pending.State != "" {
		q.Set("state", pending.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
