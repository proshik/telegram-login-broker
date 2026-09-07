// Package server is the HTTP surface of the broker: byte-compatible with
// oauth.telegram.org as far as the two consumers exercise it, so an application
// switches over by changing one environment variable.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/proshik/telegram-login-broker/internal/config"
	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
	"github.com/proshik/telegram-login-broker/internal/store"
)

// bindingCookie ties the browser that started a login to the one that comes
// back. __Host- pins it to this exact origin with no Domain and Path=/, which
// is the strongest form a cookie has. Secure is part of that prefix and holds on
// loopback too: browsers treat localhost as a secure context.
const bindingCookie = "__Host-broker_flow"

// Upstream is real Telegram in production and a stub in tests. Keeping it an
// interface is what lets the whole login be exercised without a network.
type Upstream interface {
	AuthURL(bot registry.Bot, callbackURL, state, codeChallenge string) string
	Exchange(ctx context.Context, bot registry.Bot, code, codeVerifier, callbackURL string) (oidc.Identity, error)
}

type Options struct {
	Config   config.Config
	Registry *registry.Registry
	Store    *store.Store
	Signer   *oidc.Signer
	Upstream Upstream
	Now      func() time.Time
	Logger   *slog.Logger
}

type Server struct {
	opts Options
	mux  *http.ServeMux
}

func New(o Options) (*Server, error) {
	switch {
	case o.Registry == nil:
		return nil, fmt.Errorf("server needs a registry")
	case o.Store == nil:
		return nil, fmt.Errorf("server needs a store")
	case o.Signer == nil:
		return nil, fmt.Errorf("server needs a signer")
	case !o.Config.MockEnabled && o.Upstream == nil:
		return nil, fmt.Errorf("telegram mode needs an upstream")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}

	s := &Server{opts: o, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /auth", s.handleAuth)
	s.mux.HandleFunc("POST /auth/select", s.handleSelect)
	s.mux.HandleFunc("GET /callback", s.handleCallback)
	s.mux.HandleFunc("POST /token", s.handleToken)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	// No discovery document: its issuer would have to equal the document's own
	// origin, and ours deliberately does not. Publishing it would be a lie, while
	// JWKS is a fact.
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.opts.Signer.JWKS()
	if err != nil {
		http.Error(w, "cannot render jwks", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(raw)
}

// callbackURL is the single address registered in BotFather, once per bot,
// forever. Everything else about where a login ends up is decided here.
func (s *Server) callbackURL() string {
	return strings.TrimRight(s.opts.Config.Issuer, "/") + "/callback"
}

func (s *Server) setBinding(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     bindingCookie,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		// Lax, not Strict: the browser arrives here from Telegram, and Strict
		// would withhold the cookie on exactly that navigation.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((5 * time.Minute).Seconds()),
	})
}

func (s *Server) clearBinding(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: bindingCookie, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// randomToken is used for flow ids, browser bindings, authorization codes and
// access tokens alike: 256 bits from crypto/rand, url-safe.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
