// Package config reads the settings that may only change at startup.
//
// The split is deliberate and load-bearing: bots, applications, slugs and
// allowed origins live in the registry and can be changed at runtime, while the
// two most dangerous switches — who may log in at all, and whether mock is on —
// live only here. Changing either is a restart, which is a price worth paying
// once a year for putting them out of reach of the admin interface.
package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
)

// BootstrapBot seeds the registry on a first start, so a fresh deployment can
// log in before anything has been added through the admin interface.
type BootstrapBot struct {
	Name         string
	ClientID     string
	ClientSecret string
}

type MockUser struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	PhotoURL string `json:"photo_url"`
}

type Config struct {
	Issuer       string
	Bind         string
	RegistryPath string
	RegistryKey  []byte
	SigningKey   *ecdsa.PrivateKey
	IDTokenTTL   time.Duration

	MockEnabled bool
	MockUsers   []MockUser

	VerifyUpstream     bool
	AllowedTelegramIDs []int64
	BootstrapBot       BootstrapBot
	// Clients are the applications to register on start. Until the admin
	// interface arrives in phase 7 this is the only way in: the registry file
	// cannot be edited by hand, because its secrets are sealed.
	Clients map[string]registry.Client
}

// IDAllowed is layer 4. An empty list means no restriction: a stranger then gets
// all the way through the Telegram login and is refused by the application, not
// here.
func (c Config) IDAllowed(id int64) bool {
	if len(c.AllowedTelegramIDs) == 0 {
		return true
	}
	for _, allowed := range c.AllowedTelegramIDs {
		if allowed == id {
			return true
		}
	}
	return false
}

func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Issuer:       getenv("BROKER_ISSUER"),
		Bind:         or(getenv("BROKER_BIND"), ":8080"),
		RegistryPath: or(getenv("BROKER_REGISTRY_PATH"), "/data/registry.json"),
		IDTokenTTL:   5 * time.Minute,
	}

	if cfg.Issuer == "" {
		return Config{}, fmt.Errorf("BROKER_ISSUER is required")
	}
	// Layer 7: the issuer must not be able to pass the consumers' substring
	// check, so that swapping real Telegram for the broker can never be silent.
	if strings.Contains(strings.ToLower(cfg.Issuer), "telegram") {
		return Config{}, fmt.Errorf("BROKER_ISSUER must not contain %q: an issuer that passes the consumers' substring check makes provider substitution silent", "telegram")
	}

	key, err := decodeRegistryKey(getenv("BROKER_REGISTRY_KEY"))
	if err != nil {
		return Config{}, err
	}
	cfg.RegistryKey = key

	if cfg.SigningKey, err = loadSigningKey(getenv("BROKER_SIGNING_KEY")); err != nil {
		return Config{}, err
	}

	if cfg.VerifyUpstream, err = boolOr(getenv("BROKER_VERIFY_ID_TOKEN"), true); err != nil {
		return Config{}, fmt.Errorf("BROKER_VERIFY_ID_TOKEN: %w", err)
	}
	if cfg.MockEnabled, err = boolOr(getenv("BROKER_MOCK"), false); err != nil {
		return Config{}, fmt.Errorf("BROKER_MOCK: %w", err)
	}
	if cfg.MockEnabled {
		if err := checkMockIsSafe(cfg.Bind); err != nil {
			return Config{}, err
		}
		if cfg.MockUsers, err = parseMockUsers(getenv("BROKER_MOCK_USERS")); err != nil {
			return Config{}, err
		}
	}

	if cfg.AllowedTelegramIDs, err = parseIDs(getenv("BROKER_ALLOWED_TELEGRAM_IDS")); err != nil {
		return Config{}, err
	}
	if cfg.BootstrapBot, err = parseBootstrapBot(getenv); err != nil {
		return Config{}, err
	}
	if cfg.Clients, err = parseClients(getenv("BROKER_CLIENTS")); err != nil {
		return Config{}, err
	}
	if ttl := getenv("BROKER_ID_TOKEN_TTL"); ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("BROKER_ID_TOKEN_TTL: %w", err)
		}
		cfg.IDTokenTTL = d
	}
	return cfg, nil
}

// checkMockIsSafe is layer 6. Mock on a reachable address is a "choose an
// identity" page open to the internet: PKCE and state both check out, loopback
// does not apply because the application is public, and the allow list cannot
// help because mock users must carry real ids to be useful. One click from
// anywhere is a full account takeover, and the hostname is in Certificate
// Transparency, so nobody has to guess it.
func checkMockIsSafe(bind string) error {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return fmt.Errorf("BROKER_BIND %q is not host:port: %w", bind, err)
	}
	if host == "" {
		return fmt.Errorf("mock is enabled and BROKER_BIND is %q, which listens on every interface; bind to loopback or turn mock off", bind)
	}
	if host == "localhost" {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Unmap().IsLoopback() {
		return fmt.Errorf("mock is enabled and BROKER_BIND is %q, which is not loopback; mock reachable from outside is one click from full account takeover", bind)
	}
	return nil
}

func parseMockUsers(raw string) ([]MockUser, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("BROKER_MOCK is on but BROKER_MOCK_USERS is empty; there would be nobody to log in as")
	}
	var users []MockUser
	if err := json.Unmarshal([]byte(raw), &users); err != nil {
		return nil, fmt.Errorf("BROKER_MOCK_USERS is not a JSON array of users: %w", err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("BROKER_MOCK_USERS is an empty list")
	}
	for i, u := range users {
		if u.ID == 0 {
			return nil, fmt.Errorf("BROKER_MOCK_USERS[%d] has no id; a mock user must carry the real Telegram id to be useful", i)
		}
	}
	return users, nil
}

func parseIDs(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []int64
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		id, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("BROKER_ALLOWED_TELEGRAM_IDS: %q is not a Telegram id", field)
		}
		out = append(out, id)
	}
	return out, nil
}

// parseBootstrapBot treats half a credential as fatal. Degrading into mock
// because a secret went missing is exactly the failure that must never happen
// quietly.
func parseBootstrapBot(getenv func(string) string) (BootstrapBot, error) {
	id, secret := getenv("BROKER_BOT_CLIENT_ID"), getenv("BROKER_BOT_CLIENT_SECRET")
	switch {
	case id == "" && secret == "":
		return BootstrapBot{}, nil
	case id == "" || secret == "":
		return BootstrapBot{}, fmt.Errorf("BROKER_BOT_CLIENT_ID and BROKER_BOT_CLIENT_SECRET must be set together; half a credential is never a reason to fall back to mock")
	}
	return BootstrapBot{
		Name:         or(getenv("BROKER_BOT_NAME"), "default"),
		ClientID:     id,
		ClientSecret: secret,
	}, nil
}

// parseClients reads the applications from BROKER_CLIENTS, a JSON object keyed
// by client_id. A malformed entry is fatal rather than skipped: silently
// starting without an application is a broker that turns it away at /auth with
// no hint as to why.
func parseClients(raw string) (map[string]registry.Client, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var parsed map[string]struct {
		Secret          string   `json:"secret"`
		Bot             string   `json:"bot"`
		RedirectOrigins []string `json:"redirect_origins"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("BROKER_CLIENTS is not a JSON object keyed by client_id: %w", err)
	}
	out := make(map[string]registry.Client, len(parsed))
	for name, c := range parsed {
		if c.Secret == "" {
			return nil, fmt.Errorf("BROKER_CLIENTS[%q] has no secret", name)
		}
		out[name] = registry.Client{Secret: c.Secret, Bot: c.Bot, RedirectOrigins: c.RedirectOrigins}
	}
	return out, nil
}

func decodeRegistryKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("BROKER_REGISTRY_KEY is required: it is what keeps the registry secrets useless on their own")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		return nil, fmt.Errorf("BROKER_REGISTRY_KEY is not base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("BROKER_REGISTRY_KEY decodes to %d bytes, want 32", len(key))
	}
	return key, nil
}

// loadSigningKey generates an ephemeral key when none is configured — with
// ES256 that is instant — but never falls back to one when a key was configured
// and could not be read. Silently signing with a different key than the operator
// intended is the kind of thing that is noticed weeks later.
func loadSigningKey(raw string) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(raw) == "" {
		return oidc.GenerateKey()
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("BROKER_SIGNING_KEY is not PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("BROKER_SIGNING_KEY is not a usable EC private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("BROKER_SIGNING_KEY is %T, want an EC private key for ES256", parsed)
	}
	return key, nil
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func boolOr(raw string, fallback bool) (bool, error) {
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%q is not a boolean", raw)
	}
	return v, nil
}
