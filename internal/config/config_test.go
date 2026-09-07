package config

import (
	"strings"
	"testing"
)

func baseEnv() map[string]string {
	return map[string]string{
		"BROKER_ISSUER":       "https://broker.example.com",
		"BROKER_BIND":         "127.0.0.1:8080",
		"BROKER_REGISTRY_KEY": strings.Repeat("A", 43), // 32 bytes, base64url
	}
}

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func loadWith(t *testing.T, mutate func(map[string]string)) (Config, error) {
	t.Helper()
	env := baseEnv()
	if mutate != nil {
		mutate(env)
	}
	return Load(envFunc(env))
}

func TestLoadAcceptsAMinimalTelegramSetup(t *testing.T) {
	cfg, err := loadWith(t, nil)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.MockEnabled {
		t.Error("mock is on without anyone asking for it")
	}
	if !cfg.VerifyUpstream {
		t.Error("upstream verification defaults to off; it must default to on")
	}
	if cfg.Issuer != "https://broker.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
}

func TestIssuerMustNotContainTelegram(t *testing.T) {
	// Naming the host so the consumers' `iss contains "telegram"` check passes
	// would make substituting the broker for real Telegram silent. The check has
	// to fail loudly, so the broker refuses to pretend.
	_, err := loadWith(t, func(e map[string]string) {
		e["BROKER_ISSUER"] = "https://telegram-auth.example.com"
	})
	if err == nil {
		t.Fatal("Load() accepted an issuer containing \"telegram\"")
	}
	if !strings.Contains(err.Error(), "telegram") {
		t.Errorf("error %q does not explain the issuer rule", err)
	}
}

func TestMockRefusesToStartOnANonLoopbackBind(t *testing.T) {
	// Mock on a public host is a "pick an identity" page on the internet: one
	// click from anywhere is full account takeover. Refuse, never warn.
	for _, bind := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.168.1.10:8080"} {
		_, err := loadWith(t, func(e map[string]string) {
			e["BROKER_MOCK"] = "true"
			e["BROKER_BIND"] = bind
			e["BROKER_MOCK_USERS"] = `[{"id":1,"name":"A"}]`
		})
		if err == nil {
			t.Errorf("Load() started mock bound to %s", bind)
		}
	}
}

func TestMockStartsOnLoopback(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		cfg, err := loadWith(t, func(e map[string]string) {
			e["BROKER_MOCK"] = "true"
			e["BROKER_BIND"] = bind
			e["BROKER_MOCK_USERS"] = `[{"id":987654321,"name":"Пётр","username":"petr"}]`
		})
		if err != nil {
			t.Errorf("Load() with mock on %s = %v", bind, err)
			continue
		}
		if !cfg.MockEnabled || len(cfg.MockUsers) != 1 {
			t.Errorf("mock config not applied for %s: %+v", bind, cfg)
		}
	}
}

func TestMockNeedsUsers(t *testing.T) {
	_, err := loadWith(t, func(e map[string]string) { e["BROKER_MOCK"] = "true" })
	if err == nil {
		t.Error("Load() started mock with no users to choose from")
	}
}

func TestHalfTelegramCredentialsNeverDegradeIntoMock(t *testing.T) {
	for _, half := range []map[string]string{
		{"BROKER_BOT_CLIENT_ID": "111"},
		{"BROKER_BOT_CLIENT_SECRET": "shh"},
	} {
		_, err := loadWith(t, func(e map[string]string) {
			for k, v := range half {
				e[k] = v
			}
		})
		if err == nil {
			t.Errorf("Load() accepted %v — half a credential must be fatal, never a quiet fallback", half)
		}
	}
}

func TestBothTelegramCredentialsAreAccepted(t *testing.T) {
	cfg, err := loadWith(t, func(e map[string]string) {
		e["BROKER_BOT_CLIENT_ID"] = "111"
		e["BROKER_BOT_CLIENT_SECRET"] = "shh"
		e["BROKER_BOT_NAME"] = "example_login"
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.BootstrapBot.ClientID != "111" || cfg.BootstrapBot.Name != "example_login" {
		t.Errorf("BootstrapBot = %+v", cfg.BootstrapBot)
	}
}

func TestUnparseableSigningKeyIsFatalRatherThanEphemeral(t *testing.T) {
	_, err := loadWith(t, func(e map[string]string) {
		e["BROKER_SIGNING_KEY"] = "-----BEGIN EC PRIVATE KEY-----\nnot a key\n-----END EC PRIVATE KEY-----"
	})
	if err == nil {
		t.Error("Load() fell back to an ephemeral key instead of failing on a broken one")
	}
}

func TestMissingSigningKeyMeansEphemeral(t *testing.T) {
	cfg, err := loadWith(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SigningKey == nil {
		t.Error("no signing key was generated; ES256 keygen is instant, there is no reason to skip it")
	}
}

func TestRegistryKeyMustBeThirtyTwoBytes(t *testing.T) {
	for name, key := range map[string]string{
		"missing":   "",
		"too short": strings.Repeat("A", 10),
		"not b64":   strings.Repeat("!", 43),
	} {
		if _, err := loadWith(t, func(e map[string]string) { e["BROKER_REGISTRY_KEY"] = key }); err == nil {
			t.Errorf("Load() accepted a %s registry key", name)
		}
	}
}

func TestAllowedTelegramIDsAreParsedAndValidated(t *testing.T) {
	cfg, err := loadWith(t, func(e map[string]string) {
		e["BROKER_ALLOWED_TELEGRAM_IDS"] = "987654321, 123456789"
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !cfg.IDAllowed(987654321) || !cfg.IDAllowed(123456789) {
		t.Errorf("AllowedTelegramIDs = %v", cfg.AllowedTelegramIDs)
	}
	if cfg.IDAllowed(555) {
		t.Error("IDAllowed() let through an id that is not on the list")
	}

	if _, err := loadWith(t, func(e map[string]string) {
		e["BROKER_ALLOWED_TELEGRAM_IDS"] = "987654321, not-a-number"
	}); err == nil {
		t.Error("Load() accepted a non-numeric Telegram id")
	}
}

func TestAnEmptyAllowListAdmitsEveryone(t *testing.T) {
	// An empty list is "no restriction", which is the right default for a
	// single-owner deployment that has not decided yet. It is spelled out here so
	// that the meaning is a decision and not an accident.
	cfg, err := loadWith(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IDAllowed(42) {
		t.Error("an empty allow list turned into a deny-all")
	}
}

func TestUpstreamVerificationSwitchIsExplicit(t *testing.T) {
	cfg, err := loadWith(t, func(e map[string]string) { e["BROKER_VERIFY_ID_TOKEN"] = "false" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyUpstream {
		t.Error("BROKER_VERIFY_ID_TOKEN=false did not turn verification off")
	}
	if _, err := loadWith(t, func(e map[string]string) { e["BROKER_VERIFY_ID_TOKEN"] = "maybe" }); err == nil {
		t.Error("Load() accepted a non-boolean for the verification switch")
	}
}

func TestClientsAreReadFromTheEnvironment(t *testing.T) {
	cfg, err := loadWith(t, func(e map[string]string) {
		e["BROKER_CLIENTS"] = `{
			"kotlin-app": {"secret": "app-secret-p", "bot": "kotlin-app"},
			"go-app":      {"secret": "app-secret-m"},
			"web-app":   {"secret": "app-secret-s", "redirect_origins": ["https://web-app.example.com"]}
		}`
	})
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.Clients) != 3 {
		t.Fatalf("Clients = %+v, want three", cfg.Clients)
	}
	if cfg.Clients["kotlin-app"].Bot != "kotlin-app" {
		t.Errorf("kotlin-app bot = %q", cfg.Clients["kotlin-app"].Bot)
	}
	if got := cfg.Clients["web-app"].RedirectOrigins; len(got) != 1 || got[0] != "https://web-app.example.com" {
		t.Errorf("web-app origins = %v", got)
	}
}

func TestMalformedClientsAreFatal(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":      `{`,
		"not an object": `["kotlin-app"]`,
		"no secret":     `{"kotlin-app": {"bot": "kotlin-app"}}`,
	} {
		if _, err := loadWith(t, func(e map[string]string) { e["BROKER_CLIENTS"] = raw }); err == nil {
			t.Errorf("Load() accepted %s in BROKER_CLIENTS", name)
		}
	}
}
