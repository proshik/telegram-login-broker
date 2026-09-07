package upstream

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proshik/telegram-login-broker/internal/registry"
)

var testBot = registry.Bot{ClientID: "123456789", ClientSecret: "bot-secret"}

func fixedNow() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) }

// stubTelegram stands in for oauth.telegram.org: it signs id_tokens with a key
// it also publishes, so the whole exchange runs with no network.
type stubTelegram struct {
	*httptest.Server
	key      *ecdsa.PrivateKey // published in the JWKS
	signWith *ecdsa.PrivateKey // used to sign; differs from key only in forgery tests
	claims   map[string]any
	lastForm url.Values
	lastAuth string
}

func newStubTelegram(t *testing.T) *stubTelegram {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &stubTelegram{key: key, claims: map[string]any{
		"iss":                "",
		"aud":                testBot.ClientID,
		"sub":                "1234123412341234123",
		"id":                 987654321,
		"iat":                fixedNow().Unix(),
		"exp":                fixedNow().Add(time.Hour).Unix(),
		"name":               "Пётр Кузнецов",
		"preferred_username": "petr",
		"picture":            "https://cdn4.telesco.pe/file/photo.jpg",
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		x := s.key.X.FillBytes(make([]byte, 32))
		y := s.key.Y.FillBytes(make([]byte, 32))
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "oidc-es256-1",
			"x": base64.RawURLEncoding.EncodeToString(x),
			"y": base64.RawURLEncoding.EncodeToString(y),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		s.lastForm = r.PostForm
		s.lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-opaque",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     s.sign(t, s.claims),
		})
	})
	s.signWith = key
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	s.claims["iss"] = s.URL
	return s
}

func (s *stubTelegram) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "oidc-es256-1"})
	payload, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	d := sha256.Sum256([]byte(in))
	r, sv, err := ecdsa.Sign(rand.Reader, s.signWith, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newTelegram(t *testing.T, stub *stubTelegram, verify bool) *Telegram {
	t.Helper()
	return New(stub.URL, stub.Client(), verify, fixedNow)
}

func TestAuthURLCarriesEverythingTelegramNeeds(t *testing.T) {
	stub := newStubTelegram(t)
	tg := newTelegram(t, stub, true)

	raw := tg.AuthURL(testBot, "https://broker.example.com/callback", "flow-state", "challenge-value")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(u.Path, "/auth") {
		t.Errorf("AuthURL path = %q, want the authorization endpoint", u.Path)
	}
	q := u.Query()
	for field, want := range map[string]string{
		"client_id":             testBot.ClientID,
		"redirect_uri":          "https://broker.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid profile",
		"state":                 "flow-state",
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
	} {
		if got := q.Get(field); got != want {
			t.Errorf("AuthURL %s = %q, want %q", field, got, want)
		}
	}
	if q.Get("client_secret") != "" {
		t.Error("AuthURL leaks the bot secret into a URL the browser will see")
	}
}

func TestExchangeReturnsTheIdentity(t *testing.T) {
	stub := newStubTelegram(t)
	tg := newTelegram(t, stub, true)

	id, err := tg.Exchange(context.Background(), testBot, "the-code", "the-verifier", "https://broker.example.com/callback")
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if id.ID != 987654321 {
		t.Errorf("Identity.ID = %d, want the Telegram id from the id claim", id.ID)
	}
	if id.Name != "Пётр Кузнецов" || id.Username != "petr" {
		t.Errorf("Identity = %+v", id)
	}
}

func TestExchangeAuthenticatesWithBasicAndSendsPKCE(t *testing.T) {
	stub := newStubTelegram(t)
	tg := newTelegram(t, stub, true)

	if _, err := tg.Exchange(context.Background(), testBot, "the-code", "the-verifier", "https://broker.example.com/callback"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stub.lastAuth, "Basic ") {
		t.Errorf("Authorization = %q, want HTTP Basic as the documentation specifies", stub.lastAuth)
	}
	for field, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"code_verifier": "the-verifier",
		"redirect_uri":  "https://broker.example.com/callback",
		"client_id":     testBot.ClientID,
	} {
		if got := stub.lastForm.Get(field); got != want {
			t.Errorf("token request %s = %q, want %q", field, got, want)
		}
	}
	if stub.lastForm.Get("client_secret") != "" {
		t.Error("the secret went into the body as well as the Basic header; send it once")
	}
}

func TestExchangeFailsWhenTheIDClaimIsMissing(t *testing.T) {
	// sub is a different number from id. Falling back to it would produce a
	// stable, plausible and wrong identity — the worst bug available here.
	stub := newStubTelegram(t)
	delete(stub.claims, "id")
	tg := newTelegram(t, stub, true)

	_, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback")
	if err == nil {
		t.Fatal("Exchange() succeeded with no id claim")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error %q does not name the missing claim", err)
	}
}

func TestExchangeAcceptsAStringIDClaim(t *testing.T) {
	// The documentation shows a JSON number, but the claim is absent from
	// claims_supported, so its type is not something to bet the login on.
	stub := newStubTelegram(t)
	stub.claims["id"] = "987654321"
	tg := newTelegram(t, stub, true)

	id, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback")
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if id.ID != 987654321 {
		t.Errorf("Identity.ID = %d", id.ID)
	}
}

func TestExchangeRejectsAForgedToken(t *testing.T) {
	stub := newStubTelegram(t)
	forger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The JWKS still publishes the genuine key; only the signature is forged.
	stub.signWith = forger

	tg := newTelegram(t, stub, true)
	if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err == nil {
		t.Error("Exchange() accepted an id_token signed by a key that is not in the JWKS")
	}
}

func TestVerificationSwitchIsRealAndExplicit(t *testing.T) {
	// With verification off the same forged token goes through. The test exists
	// to prove the emergency switch actually switches something, so nobody has
	// to wonder whether verification was ever on.
	stub := newStubTelegram(t)
	forger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub.signWith = forger

	tg := newTelegram(t, stub, false)
	id, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback")
	if err != nil {
		t.Fatalf("Exchange() with verification off = %v", err)
	}
	if id.ID != 987654321 {
		t.Errorf("Identity.ID = %d", id.ID)
	}
}

func TestExchangeRejectsAnExpiredToken(t *testing.T) {
	stub := newStubTelegram(t)
	stub.claims["exp"] = fixedNow().Add(-time.Minute).Unix()
	tg := newTelegram(t, stub, true)

	if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err == nil {
		t.Error("Exchange() accepted an expired id_token")
	}
}

func TestExchangeRejectsAnUnexpectedIssuer(t *testing.T) {
	stub := newStubTelegram(t)
	stub.claims["iss"] = "https://not-telegram.example.com"
	tg := newTelegram(t, stub, true)

	if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err == nil {
		t.Error("Exchange() accepted an id_token from another issuer")
	}
}

func TestExchangeSurfacesAnUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(srv.Close)

	tg := New(srv.URL, srv.Client(), false, fixedNow)
	if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err == nil {
		t.Error("Exchange() ignored a 400 from the token endpoint")
	}
}

func TestClaimSetIsLoggedOnFirstUpstreamToken(t *testing.T) {
	// The plan makes this the prerequisite for tightening the consumers: before
	// anyone makes iss/aud/exp mandatory, somebody has to look at what real
	// Telegram actually sends. Claim *names* only — the values are the person who
	// just logged in, and logs are the wrong place for them.
	stub := newStubTelegram(t)
	var logged bytes.Buffer
	tg := New(stub.URL, stub.Client(), true, fixedNow)
	tg.SetLogger(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err != nil {
		t.Fatal(err)
	}

	out := logged.String()
	if !strings.Contains(out, "upstream id_token claim set") {
		t.Fatalf("the claim set was not logged: %s", out)
	}
	for _, claim := range []string{"iss", "aud", "sub", "id", "exp", "name", "preferred_username", "picture"} {
		if !strings.Contains(out, claim) {
			t.Errorf("claim %q is missing from the logged set: %s", claim, out)
		}
	}
	// The values must not be there. A photo URL and a display name are the person.
	for _, value := range []string{"Пётр Кузнецов", "petr", "1234123412341234123", "987654321"} {
		if strings.Contains(out, value) {
			t.Errorf("claim value %q leaked into the log: %s", value, out)
		}
	}
}

func TestTheClaimSetIsLoggedOnceNotPerLogin(t *testing.T) {
	// It is a one-off observation, not a running commentary on every login.
	stub := newStubTelegram(t)
	var logged bytes.Buffer
	tg := New(stub.URL, stub.Client(), true, fixedNow)
	tg.SetLogger(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo})))

	for range 3 {
		if _, err := tg.Exchange(context.Background(), testBot, "c", "v", "https://broker.example.com/callback"); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logged.String(), "upstream id_token claim set"); n != 1 {
		t.Errorf("the claim set was logged %d times, want once", n)
	}
}
