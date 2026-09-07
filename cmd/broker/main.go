// Command broker is the login broker: one permanent public HTTPS address,
// registered in BotFather once, that redirects the browser on to whatever
// loopback port a project happens to use today.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/proshik/telegram-login-broker/internal/config"
	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
	"github.com/proshik/telegram-login-broker/internal/server"
	"github.com/proshik/telegram-login-broker/internal/store"
	"github.com/proshik/telegram-login-broker/internal/upstream"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		// Every startup failure lands here, and every message it carries names
		// the thing to fix. Refusing to start is the point: a broker that came up
		// degraded would be trusted exactly as much as one that came up right.
		logger.Error("broker did not start", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	reg, err := openRegistry(cfg, logger)
	if err != nil {
		return err
	}
	if err := reg.EnsureClients(cfg.Clients); err != nil {
		return fmt.Errorf("registering applications from BROKER_CLIENTS: %w", err)
	}

	signer, err := oidc.NewSigner(cfg.SigningKey, cfg.Issuer, cfg.IDTokenTTL, time.Now)
	if err != nil {
		return err
	}

	// The code TTL is 60s because Traefik writes the code-bearing redirect into
	// its access log; the pending window is longer because it holds a person
	// deciding whether to log in.
	sessions := store.New(time.Now, 5*time.Minute, 60*time.Second)

	opts := server.Options{
		Config:   cfg,
		Registry: reg,
		Store:    sessions,
		Signer:   signer,
		Now:      time.Now,
		Logger:   logger,
	}
	if !cfg.MockEnabled {
		tg := upstream.New(upstream.DefaultBaseURL, nil, cfg.VerifyUpstream, time.Now)
		tg.SetLogger(logger)
		opts.Upstream = tg
		if !cfg.VerifyUpstream {
			logger.Warn("upstream id_token verification is OFF; whoever answers as Telegram decides who logs in")
		}
	}
	handler, err := server.New(opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	limiter := server.NewRateLimiter(60, time.Minute, time.Now)
	guarded := server.MockExposureGuard(limiter.Middleware(handler), cfg.MockEnabled, func() {
		logger.Error("mock mode received a proxied request, so it is reachable from outside; shutting down")
		stop()
	})

	httpServer := &http.Server{
		Addr:    cfg.Bind,
		Handler: guarded,
		// A zero-valued http.Server has no timeouts at all, which is slowloris
		// out of the box.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	go janitor(ctx, sessions, limiter)

	mode := "telegram"
	if cfg.MockEnabled {
		mode = "mock"
	}
	logger.Info("broker listening",
		"bind", cfg.Bind, "mode", mode, "issuer", cfg.Issuer,
		"callback", strings.TrimRight(cfg.Issuer, "/")+"/callback",
		"allowed_ids", len(cfg.AllowedTelegramIDs))

	errs := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

// openRegistry loads the registry, or writes a first one from the bootstrap
// credentials so that a fresh deployment can log in before anything has been
// added through the admin interface.
func openRegistry(cfg config.Config, logger *slog.Logger) (*registry.Registry, error) {
	box, err := registry.NewBox(cfg.RegistryKey)
	if err != nil {
		return nil, err
	}

	reg, err := registry.Load(cfg.RegistryPath, box)
	if err == nil {
		return reg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// A registry that cannot be read is never replaced with an empty one: an
		// empty registry is a broker that turns every application away, and doing
		// that quietly is worse than not starting.
		return nil, fmt.Errorf("cannot read the registry: %w", err)
	}
	bot := registry.Bot{
		ClientID:     cfg.BootstrapBot.ClientID,
		ClientSecret: cfg.BootstrapBot.ClientSecret,
	}
	name := cfg.BootstrapBot.Name
	switch {
	case bot.ClientID != "":
		logger.Info("no registry yet; creating one from the bootstrap bot", "path", cfg.RegistryPath, "bot", name)
	case cfg.MockEnabled:
		// Mock never talks to Telegram, so demanding real bot credentials to
		// start it would defeat the point of an offline mode. The placeholder
		// exists only to give clients something to resolve to.
		name = "mock"
		logger.Info("no registry yet; creating one with a placeholder bot for mock mode", "path", cfg.RegistryPath)
	default:
		return nil, fmt.Errorf("no registry at %s and no BROKER_BOT_CLIENT_ID/BROKER_BOT_CLIENT_SECRET to create one from", cfg.RegistryPath)
	}

	return registry.Create(cfg.RegistryPath, box, registry.Data{
		DefaultBot: name,
		Bots:       map[string]registry.Bot{name: bot},
		Clients:    map[string]registry.Client{},
		Slugs:      map[string]registry.Slug{},
	})
}

// janitor only returns memory. Nothing about the flow's correctness depends on
// it running, because expiry is decided on every read.
func janitor(ctx context.Context, sessions *store.Store, limiter *server.RateLimiter) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sessions.Sweep()
			limiter.Sweep()
		}
	}
}
