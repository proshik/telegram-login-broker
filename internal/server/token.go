package server

import (
	"crypto/subtle"
	"encoding/json"
	"mime"
	"net/http"

	"github.com/proshik/telegram-login-broker/internal/oidc"
)

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// The cap goes on before ParseForm, or the body is already in memory by the
	// time anyone objects to its size.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	// Feign appends ";charset=UTF-8"; comparing the header with == would reject
	// every request kotlin-app makes.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			tokenError(w, http.StatusBadRequest, "invalid_request", "expected application/x-www-form-urlencoded")
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	// PostForm, never Form: Form merges the query string, which would let a code
	// arrive through the URL and land in every access log on the way.
	form := r.PostForm

	if form.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	// Taken first, before any validation: the code is spent by the attempt, not
	// by the success. A wrong verifier burns it, which is what OAuth 2.1 asks
	// for and what makes replay impossible without a compare-and-swap.
	issued, ok := s.opts.Store.TakeCode(form.Get("code"))
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already used code")
		return
	}

	clientID := form.Get("client_id")
	client, _, err := s.opts.Registry.ResolveClient(clientID)
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	// Layer 2. Constant time, because the comparison is against a secret.
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(form.Get("client_secret"))) != 1 {
		s.opts.Logger.Warn("bad client_secret on /token", "client_id", clientID)
		tokenError(w, http.StatusBadRequest, "invalid_client", "bad client_secret")
		return
	}
	if issued.ClientID != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "this code belongs to another client")
		return
	}
	// RFC 6749 §4.1.3: the same redirect_uri, compared byte for byte.
	if issued.RedirectURI != form.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the one used at /auth")
		return
	}
	if err := oidc.VerifyPKCE(issued.CodeChallenge, form.Get("code_verifier")); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	}

	idToken, err := s.opts.Signer.MintIDToken(clientID, issued.Identity)
	if err != nil {
		s.opts.Logger.Error("cannot mint id_token", "client_id", clientID, "err", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "cannot mint id_token")
		return
	}
	// Opaque on purpose. Nothing accepts this token anywhere, so it must not look
	// like a JWT and invite someone to read it.
	accessToken, err := randomToken()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "cannot mint access_token")
		return
	}

	s.opts.Logger.Info("issued id_token", "client_id", clientID, "telegram_id", issued.Identity.ID)

	// Exactly these three keys. access_token and token_type are non-null in
	// kotlin-app's Kotlin TokenResponse, so dropping either breaks
	// deserialization before the application ever sees the token; extra keys buy
	// nothing and risk someone else's Jackson configuration.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"id_token":     idToken,
	})
}

func tokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
