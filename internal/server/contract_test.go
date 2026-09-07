package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file holds a verbatim copy of go-app's id_token parser
// (internal/web/oidc.go), run against the broker's real /token output. Contract
// drift between the two shows up here rather than in a browser.
//
// Do not tidy this copy. The moment it stops being a copy it stops proving
// anything.

type telegramUser struct {
	ID        int64
	FirstName string
	Username  string
	PhotoURL  string
}

func parseIDTokenGoApp(raw, clientID string) (*telegramUser, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected id_token format: got %d segments, want 3", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id_token payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse id_token claims: %w", err)
	}

	if exp, ok := claims["exp"].(float64); ok && int64(exp) <= time.Now().Unix() {
		return nil, fmt.Errorf("id_token has expired")
	}
	if aud, ok := claims["aud"].(string); ok && aud != clientID {
		return nil, fmt.Errorf("id_token aud mismatch")
	}
	if iss, ok := claims["iss"].(string); ok && !strings.Contains(strings.ToLower(iss), "telegram") {
		return nil, fmt.Errorf("id_token iss mismatch: %s", iss)
	}

	id, err := claimInt64(claims["id"])
	if err != nil {
		return nil, fmt.Errorf("id_token 'id' claim: %w", err)
	}

	return &telegramUser{
		ID:        id,
		FirstName: claimString(claims["name"]),
		Username:  claimString(claims["preferred_username"]),
		PhotoURL:  claimString(claims["picture"]),
	}, nil
}

func claimInt64(v any) (int64, error) {
	switch t := v.(type) {
	case float64:
		return int64(t), nil
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("not a number: %q", t)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("missing or of unexpected type %T", v)
	}
}

func claimString(v any) string {
	s, _ := v.(string)
	return s
}

// --- the contract ------------------------------------------------------------

func (h *harness) idTokenFor(t *testing.T, q url.Values) string {
	t.Helper()
	code := h.codeFor(t, q, "987654321")
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(body(t, h.postToken(t, tokenForm(code)))), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.IDToken == "" {
		t.Fatal("no id_token in the token response")
	}
	return payload.IDToken
}

func TestGoAppParserReadsEverythingButTheIssuer(t *testing.T) {
	// Everything structural has to hold: three segments, no padding, an id claim
	// of the right type, aud as a bare string. The parser is run with the issuer
	// check lifted, so a failure here is a real contract break rather than the
	// deliberate issuer choice.
	h := newHarness(t, nil)
	idToken := h.idTokenFor(t, authQuery())

	parts := strings.Split(idToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("go-app's strict RawURLEncoding cannot read the payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if aud, ok := claims["aud"].(string); !ok || aud != appClientID {
		t.Errorf("aud = %#v; as anything but a string the audience check silently stops running", claims["aud"])
	}
	id, err := claimInt64(claims["id"])
	if err != nil {
		t.Fatalf("go-app cannot read the id claim: %v", err)
	}
	if id != 987654321 {
		t.Errorf("id = %d, want 987654321", id)
	}
	if claimString(claims["name"]) != "Пётр Кузнецов" {
		t.Errorf("name = %q; Cyrillic did not survive", claimString(claims["name"]))
	}
}

func TestGoAppParserStillRejectsTheIssuerUntilPhaseTwo(t *testing.T) {
	// This failure is the plan working as intended, not a bug. The issuer is
	// deliberately free of the substring "telegram" so that swapping the real
	// provider for the broker can never happen silently — which means phase 2,
	// where both consumers switch to an exact expected-issuer check, has to ship
	// alongside this. Until it does, the login fails on its last step.
	//
	// When phase 2 lands and this test starts failing, delete it. That failure is
	// the signal that the consumers no longer need it.
	h := newHarness(t, nil)
	idToken := h.idTokenFor(t, authQuery())

	_, err := parseIDTokenGoApp(idToken, appClientID)
	if err == nil {
		t.Fatal("go-app's current parser accepted the broker's issuer; either phase 2 shipped or the issuer rule was quietly broken")
	}
	if !strings.Contains(err.Error(), "iss mismatch") {
		t.Errorf("go-app rejected the token for %q, want the issuer check — anything else is a real contract break", err)
	}
}

func TestGoAppParserAcceptsTheTokenUnderPhaseTwoRules(t *testing.T) {
	// Phase 2 replaces "iss contains telegram" with exact equality against a
	// configured expected-issuer. Under that rule the very same token parses.
	h := newHarness(t, nil)
	idToken := h.idTokenFor(t, authQuery())

	parts := strings.Split(idToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}

	const expectedIssuer = "https://broker.example.com"
	iss, ok := claims["iss"].(string)
	if !ok {
		t.Fatal("phase 2 makes iss mandatory, and it is absent")
	}
	if iss != expectedIssuer {
		t.Errorf("iss = %q, want exactly %q", iss, expectedIssuer)
	}
	if _, ok := claims["aud"].(string); !ok {
		t.Error("phase 2 makes aud mandatory as a string")
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Error("phase 2 makes exp mandatory")
	}
}
