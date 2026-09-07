package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/proshik/telegram-login-broker/internal/oidc"
)

// A reference implementation of a strict consumer's id_token parser, run against
// the broker's real /token output. It is deliberately written the way a careful
// consumer would write it — every claim mandatory, the issuer compared byte for
// byte — and kept identical to the parser in the application that actually uses
// this broker.
//
// Do not tidy it. Its only value is being the same code as the one in
// production; the moment the two diverge, this proves nothing. Contract drift
// shows up here rather than in a browser.

type telegramUser struct {
	ID        int64
	FirstName string
	Username  string
	PhotoURL  string
}

const clockSkew = 60 * time.Second

func parseIDTokenStrictConsumer(raw, clientID, expectedIssuer string) (*telegramUser, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("unexpected id_token format: got %d segments, want 3", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id_token payload: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("parse id_token claims: %w", err)
	}

	iss, _ := claims["iss"].(string)
	if iss == "" {
		return nil, fmt.Errorf("id_token has no iss claim")
	}
	if iss != expectedIssuer {
		return nil, fmt.Errorf("id_token iss is %q, want %q", iss, expectedIssuer)
	}

	if err := checkAudience(claims["aud"], clientID); err != nil {
		return nil, err
	}

	exp, err := claimUnix(claims["exp"])
	if err != nil {
		return nil, fmt.Errorf("id_token exp claim: %w", err)
	}
	now := time.Now()
	if !now.Before(exp) {
		return nil, fmt.Errorf("id_token has expired")
	}
	if raw, present := claims["iat"]; present {
		iat, err := claimUnix(raw)
		if err != nil {
			return nil, fmt.Errorf("id_token iat claim: %w", err)
		}
		if iat.After(now.Add(clockSkew)) {
			return nil, fmt.Errorf("id_token iat is %s, which is in the future", iat)
		}
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

func checkAudience(v any, clientID string) error {
	switch aud := v.(type) {
	case string:
		if aud != clientID {
			return fmt.Errorf("id_token aud is %q, want %q", aud, clientID)
		}
		return nil
	case []any:
		for _, entry := range aud {
			if s, ok := entry.(string); ok && s == clientID {
				return nil
			}
		}
		return fmt.Errorf("id_token aud %v does not contain %q", aud, clientID)
	case nil:
		return fmt.Errorf("id_token has no aud claim")
	default:
		return fmt.Errorf("id_token aud is a %T, want a string or an array of strings", v)
	}
}

func claimUnix(v any) (time.Time, error) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("not a whole number: %q", t)
		}
		return time.Unix(n, 0), nil
	case float64:
		return time.Unix(int64(t), 0), nil
	case nil:
		return time.Time{}, fmt.Errorf("missing")
	default:
		return time.Time{}, fmt.Errorf("is a %T, want a number", v)
	}
}

func claimInt64(v any) (int64, error) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0, fmt.Errorf("not a whole number: %q", t)
		}
		return n, nil
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

const brokerIssuer = "https://broker.example.com"

// newContractHarness signs on the real clock. Everywhere else the tests freeze
// time, but the consumer's parser calls time.Now(), so exp and iat have to be
// measured against the same clock it uses or the comparison proves nothing.
func newContractHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, func(o *Options) {
		key, err := oidc.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		signer, err := oidc.NewSigner(key, brokerIssuer, 5*time.Minute, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		o.Signer = signer
	})
}

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

func TestAStrictConsumerAcceptsTheBrokersToken(t *testing.T) {
	// The whole point: with the broker's issuer configured, a strict consumer
	// reads the broker's real token and gets the right person.
	h := newContractHarness(t)
	idToken := h.idTokenFor(t, authQuery())

	user, err := parseIDTokenStrictConsumer(idToken, appClientID, brokerIssuer)
	if err != nil {
		t.Fatalf("a strict consumer rejected the broker's id_token: %v", err)
	}
	if user.ID != 987654321 {
		t.Errorf("ID = %d, want 987654321", user.ID)
	}
	if user.FirstName != "Пётр Кузнецов" {
		t.Errorf("FirstName = %q; Cyrillic did not survive", user.FirstName)
	}
	if user.Username != "petr" {
		t.Errorf("Username = %q", user.Username)
	}
}

func TestPointingAtTheBrokerHasToBeConfigured(t *testing.T) {
	// Left on Telegram's issuer, the same token is refused. That is the property
	// the deliberately non-"telegram" issuer buys: a broker cannot be slipped in
	// behind an application that was not reconfigured for it.
	h := newContractHarness(t)
	idToken := h.idTokenFor(t, authQuery())

	_, err := parseIDTokenStrictConsumer(idToken, appClientID, "https://oauth.telegram.org")
	if err == nil {
		t.Fatal("a strict consumer accepted the broker's token while configured for Telegram")
	}
	if !strings.Contains(err.Error(), "iss") {
		t.Errorf("refused for %q, want the issuer check", err)
	}
}

func TestTheBrokersTokenSatisfiesEveryMandatoryClaim(t *testing.T) {
	// Each of these is now mandatory in both consumers, so a token missing one is
	// no longer merely unchecked — it is refused.
	h := newContractHarness(t)
	idToken := h.idTokenFor(t, authQuery())

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(idToken, ".")[1])
	if err != nil {
		t.Fatalf("strict RawURLEncoding cannot read the payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if iss, _ := claims["iss"].(string); iss != brokerIssuer {
		t.Errorf("iss = %#v, want exactly %q", claims["iss"], brokerIssuer)
	}
	if aud, ok := claims["aud"].(string); !ok || aud != appClientID {
		t.Errorf("aud = %#v; as anything but a string the audience check used to stop running silently", claims["aud"])
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Error("exp is missing or not a number")
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Error("iat is missing or not a number")
	}
	if id, err := claimInt64(claims["id"]); err != nil || id != 987654321 {
		t.Errorf("id = %#v (%v)", claims["id"], err)
	}
}
