package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/proshik/telegram-login-broker/internal/config"
	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
	"github.com/proshik/telegram-login-broker/internal/store"
)

const (
	appSecret   = "app-secret"
	appClientID = "kotlin-app"
	appRedirect = "http://localhost:8080/auth/telegram/callback"
	// RFC 7636 Appendix B, so the pair is known-good independently of our code.
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type harness struct {
	*httptest.Server
	client *http.Client
}

func newHarness(t *testing.T, mutate func(*Options)) *harness {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	box, err := registry.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Create(filepath.Join(t.TempDir(), "registry.json"), box, registry.Data{
		DefaultBot: "example_login",
		Bots:       map[string]registry.Bot{"example_login": {ClientID: "111", ClientSecret: "bot-secret"}},
		Clients: map[string]registry.Client{
			appClientID: {Secret: appSecret},
			"web-app":   {Secret: "s", RedirectOrigins: []string{"https://web-app.example.com"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	signKey, err := oidc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) }
	signer, err := oidc.NewSigner(signKey, "https://broker.example.com", 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Config: config.Config{
			Issuer:      "https://broker.example.com",
			MockEnabled: true,
			MockUsers: []config.MockUser{
				{ID: 987654321, Name: "Пётр Кузнецов", Username: "petr"},
				{ID: 111222333, Name: "Вторая личность"},
			},
		},
		Registry: reg,
		Store:    store.New(now, 5*time.Minute, 60*time.Second),
		Signer:   signer,
		Now:      now,
	}
	if mutate != nil {
		mutate(&opts)
	}
	h, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &harness{Server: srv, client: &http.Client{
		// Every redirect in this flow is a step under test; never follow one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func authQuery() url.Values {
	return url.Values{
		"client_id":             {appClientID},
		"redirect_uri":          {appRedirect},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {"app-state-value"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

func (h *harness) get(t *testing.T, path string, q url.Values) *http.Response {
	t.Helper()
	u := h.URL + path
	if q != nil {
		u += "?" + q.Encode()
	}
	resp, err := h.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("segment %q is not raw base64url: %v", seg, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("segment is not JSON: %v", err)
	}
	return m
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// startLogin walks /auth and returns the flow id from the chooser page plus the
// binding cookie the browser was handed.
func (h *harness) startLogin(t *testing.T, q url.Values) (flow string, cookie *http.Cookie) {
	t.Helper()
	resp := h.get(t, "/auth", q)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth = %d, want 200; body=%s", resp.StatusCode, body(t, resp))
	}
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-") {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("GET /auth set no __Host- binding cookie")
	}
	page := body(t, resp)
	const marker = `name="flow" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("chooser page carries no flow id: %s", page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)], cookie
}

func (h *harness) selectUser(t *testing.T, flow string, cookie *http.Cookie, id string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.URL+"/auth/select",
		strings.NewReader(url.Values{"flow": {flow}, "id": {id}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (h *harness) postToken(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	resp, err := h.client.PostForm(h.URL+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func tokenForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {appRedirect},
		"client_id":     {appClientID},
		"client_secret": {appSecret},
		"code_verifier": {verifier},
	}
}

// --- /auth -------------------------------------------------------------------

func TestAuthRefusesAnUnregisteredClientWithoutRedirecting(t *testing.T) {
	h := newHarness(t, nil)
	q := authQuery()
	q.Set("client_id", "not-registered")

	resp := h.get(t, "/auth", q)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /auth = %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("refusal carried Location: %q — an unvalidated redirect_uri must never be honoured", loc)
	}
}

func TestAuthRefusesABadRedirectURIWithoutRedirecting(t *testing.T) {
	h := newHarness(t, nil)
	for _, bad := range []string{
		"http://localhost@evil.com/cb",
		"https://app.example.com/cb",
		"http://2130706433/cb",
		"//evil.com/cb",
	} {
		q := authQuery()
		q.Set("redirect_uri", bad)

		resp := h.get(t, "/auth", q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET /auth with redirect_uri=%s = %d, want 400", bad, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("redirect_uri=%s produced Location: %q", bad, loc)
		}
	}
}

func TestAuthAcceptsAnAllowListedOrigin(t *testing.T) {
	h := newHarness(t, nil)
	q := authQuery()
	q.Set("client_id", "web-app")
	q.Set("redirect_uri", "https://web-app.example.com/auth/cb")

	if resp := h.get(t, "/auth", q); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /auth = %d, want 200 for a listed origin", resp.StatusCode)
	}
}

func TestAuthValidatesTheProtocolParameters(t *testing.T) {
	h := newHarness(t, nil)
	cases := map[string]func(url.Values){
		"missing client_id":      func(q url.Values) { q.Del("client_id") },
		"missing redirect_uri":   func(q url.Values) { q.Del("redirect_uri") },
		"response_type token":    func(q url.Values) { q.Set("response_type", "token") },
		"plain challenge method": func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"missing challenge":      func(q url.Values) { q.Del("code_challenge") },
		"short challenge":        func(q url.Values) { q.Set("code_challenge", "too-short") },
		"oversized state":        func(q url.Values) { q.Set("state", strings.Repeat("s", 513)) },
		"oversized client_id":    func(q url.Values) { q.Set("client_id", strings.Repeat("c", 129)) },
	}
	for name, mutate := range cases {
		q := authQuery()
		mutate(q)
		resp := h.get(t, "/auth", q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: GET /auth = %d, want 400", name, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("%s: refusal carried Location %q", name, loc)
		}
	}
}

// --- mock flow ---------------------------------------------------------------

func TestMockFlowRedirectsBackWithACodeAndTheOriginalState(t *testing.T) {
	h := newHarness(t, nil)
	flow, cookie := h.startLogin(t, authQuery())

	resp := h.selectUser(t, flow, cookie, "987654321")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /auth/select = %d, want 302; body=%s", resp.StatusCode, body(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != appRedirect {
		t.Errorf("Location = %s, want a redirect to %s", loc, appRedirect)
	}
	if got := loc.Query().Get("state"); got != "app-state-value" {
		t.Errorf("state = %q, want the application's own state echoed back", got)
	}
	if loc.Query().Get("code") == "" {
		t.Error("no code in the callback")
	}
}

func TestMockSelectRequiresTheBindingCookie(t *testing.T) {
	// Without it /callback is open to login-CSRF: upstream state alone cannot
	// tell "the same browser came back" from "an attacker logged in and handed
	// over the link".
	h := newHarness(t, nil)
	flow, _ := h.startLogin(t, authQuery())

	if resp := h.selectUser(t, flow, nil, "987654321"); resp.StatusCode == http.StatusFound {
		t.Error("POST /auth/select completed a login with no binding cookie")
	}
}

func TestMockSelectRejectsAForeignBindingCookie(t *testing.T) {
	h := newHarness(t, nil)
	flow, _ := h.startLogin(t, authQuery())
	_, otherCookie := h.startLogin(t, authQuery())

	if resp := h.selectUser(t, flow, otherCookie, "987654321"); resp.StatusCode == http.StatusFound {
		t.Error("POST /auth/select accepted a binding cookie from a different browser session")
	}
}

func TestMockSelectRejectsAnUnlistedUser(t *testing.T) {
	h := newHarness(t, nil)
	flow, cookie := h.startLogin(t, authQuery())

	if resp := h.selectUser(t, flow, cookie, "424242"); resp.StatusCode == http.StatusFound {
		t.Error("POST /auth/select accepted an id that is not a configured mock user")
	}
}

func TestRefusedTelegramIDNeverReachesTheApplication(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.Config.AllowedTelegramIDs = []int64{111222333}
	})
	flow, cookie := h.startLogin(t, authQuery())

	resp := h.selectUser(t, flow, cookie, "987654321")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /auth/select = %d, want 403 for an id outside the allow list", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("refusal carried Location %q", loc)
	}
}

// --- /token ------------------------------------------------------------------

func (h *harness) codeFor(t *testing.T, q url.Values, id string) string {
	t.Helper()
	flow, cookie := h.startLogin(t, q)
	resp := h.selectUser(t, flow, cookie, id)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code")
}

func TestTokenReturnsExactlyThreeKeys(t *testing.T) {
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	resp := h.postToken(t, tokenForm(code))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token = %d; body=%s", resp.StatusCode, body(t, resp))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body(t, resp)), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 {
		t.Errorf("token response has %d keys (%v), want exactly access_token, token_type and id_token", len(payload), payload)
	}
	for _, k := range []string{"access_token", "token_type", "id_token"} {
		if v, _ := payload[k].(string); v == "" {
			t.Errorf("token response %s is missing or empty; both consumers fail deserialization before they ever see the token", k)
		}
	}
	if payload["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", payload["token_type"])
	}
	if strings.Contains(payload["id_token"].(string), "=") {
		t.Error("id_token carries base64 padding; go-app's RawURLEncoding refuses it")
	}
	if strings.Count(payload["access_token"].(string), ".") == 2 {
		t.Error("access_token looks like a JWT; it is opaque and nothing accepts it, so it must not pretend otherwise")
	}
}

func TestTokenBurnsTheCodeOnFirstUse(t *testing.T) {
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	if resp := h.postToken(t, tokenForm(code)); resp.StatusCode != http.StatusOK {
		t.Fatalf("first exchange = %d", resp.StatusCode)
	}
	if resp := h.postToken(t, tokenForm(code)); resp.StatusCode == http.StatusOK {
		t.Error("the same code was exchanged twice")
	}
}

func TestAWrongVerifierBurnsTheCodeToo(t *testing.T) {
	// OAuth 2.1: a failed exchange consumes the code. Otherwise an attacker who
	// stole the code can keep guessing.
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	bad := tokenForm(code)
	bad.Set("code_verifier", "wrong-verifier-entirely-but-long-enough-here")
	if resp := h.postToken(t, bad); resp.StatusCode == http.StatusOK {
		t.Fatal("POST /token accepted a wrong code_verifier")
	}
	if resp := h.postToken(t, tokenForm(code)); resp.StatusCode == http.StatusOK {
		t.Error("the correct verifier still worked after a failed attempt; the code was not burned")
	}
}

func TestTokenChecksTheClientSecret(t *testing.T) {
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	bad := tokenForm(code)
	bad.Set("client_secret", "not-the-secret")
	if resp := h.postToken(t, bad); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /token with a wrong client_secret = %d, want 400", resp.StatusCode)
	}
}

func TestTokenRejectsAMismatchedRedirectURIAndClientID(t *testing.T) {
	h := newHarness(t, nil)

	code := h.codeFor(t, authQuery(), "987654321")
	mismatched := tokenForm(code)
	mismatched.Set("redirect_uri", "http://localhost:9999/auth/telegram/callback")
	if resp := h.postToken(t, mismatched); resp.StatusCode == http.StatusOK {
		t.Error("POST /token accepted a redirect_uri that differs from the one bound to the code")
	}

	code = h.codeFor(t, authQuery(), "987654321")
	wrongClient := tokenForm(code)
	wrongClient.Set("client_id", "web-app")
	wrongClient.Set("client_secret", "s")
	if resp := h.postToken(t, wrongClient); resp.StatusCode == http.StatusOK {
		t.Error("POST /token let one client redeem another client's code")
	}
}

func TestTokenIgnoresQueryStringParameters(t *testing.T) {
	// r.Form merges the query string into the form; only r.PostForm may be read,
	// or a code can be smuggled in through the URL.
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	form := tokenForm(code)
	form.Del("code")
	resp, err := h.client.PostForm(h.URL+"/token?code="+url.QueryEscape(code), form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("POST /token read the code from the query string")
	}
}

func TestTokenAcceptsFeignsCharsetSuffix(t *testing.T) {
	// Feign sends "application/x-www-form-urlencoded;charset=UTF-8"; comparing the
	// header with == rejects every request kotlin-app makes.
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	req, err := http.NewRequest(http.MethodPost, h.URL+"/token", strings.NewReader(tokenForm(code).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /token = %d for Feign's Content-Type", resp.StatusCode)
	}
}

func TestTokenRejectsAnUnknownGrantType(t *testing.T) {
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	form := tokenForm(code)
	form.Set("grant_type", "client_credentials")
	if resp := h.postToken(t, form); resp.StatusCode == http.StatusOK {
		t.Error("POST /token honoured a grant type it does not implement")
	}
}

func TestIDTokenCarriesTheChosenIdentity(t *testing.T) {
	h := newHarness(t, nil)
	code := h.codeFor(t, authQuery(), "987654321")

	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal([]byte(body(t, h.postToken(t, tokenForm(code)))), &payload); err != nil {
		t.Fatal(err)
	}
	claims := decodeSegment(t, strings.Split(payload.IDToken, ".")[1])
	if id, _ := claims["id"].(float64); int64(id) != 987654321 {
		t.Errorf("claim id = %v, want the chosen mock user", claims["id"])
	}
	if aud, _ := claims["aud"].(string); aud != appClientID {
		t.Errorf("claim aud = %#v, want the application's own client_id as a string", claims["aud"])
	}
	if name, _ := claims["name"].(string); name != "Пётр Кузнецов" {
		t.Errorf("claim name = %q", name)
	}
}

// --- plumbing ----------------------------------------------------------------

func TestHealthzAndJWKS(t *testing.T) {
	h := newHarness(t, nil)

	if resp := h.get(t, "/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d", resp.StatusCode)
	}

	resp := h.get(t, "/.well-known/jwks.json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json = %d", resp.StatusCode)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body(t, resp)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 {
		t.Errorf("JWKS holds %d keys, want 1", len(doc.Keys))
	}
}

func TestDiscoveryDocumentIsNotServed(t *testing.T) {
	// Its issuer would have to equal the document's own origin, and ours does not
	// (layer 7). Serving it would be a lie; JWKS is a fact, so that is served.
	h := newHarness(t, nil)
	if resp := h.get(t, "/.well-known/openid-configuration", nil); resp.StatusCode == http.StatusOK {
		t.Error("the broker serves a discovery document it cannot honour")
	}
}
