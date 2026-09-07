package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
)

// stubUpstream lets the whole telegram-mode flow run with no network, and
// records what the broker sent so the two halves of its own PKCE pair can be
// compared.
type stubUpstream struct {
	identity  oidc.Identity
	err       error
	state     string
	challenge string
	verifier  string
	callback  string
}

func (s *stubUpstream) AuthURL(_ registry.Bot, callbackURL, state, codeChallenge string) string {
	s.state, s.challenge, s.callback = state, codeChallenge, callbackURL
	return "https://telegram.test/auth?state=" + url.QueryEscape(state)
}

func (s *stubUpstream) Exchange(_ context.Context, _ registry.Bot, _, codeVerifier, _ string) (oidc.Identity, error) {
	s.verifier = codeVerifier
	return s.identity, s.err
}

func newTelegramHarness(t *testing.T, up *stubUpstream) *harness {
	t.Helper()
	return newHarness(t, func(o *Options) {
		o.Config.MockEnabled = false
		o.Config.MockUsers = nil
		o.Upstream = up
	})
}

// startUpstreamLogin walks /auth in telegram mode and returns the state the
// broker handed to Telegram plus the binding cookie it gave the browser.
func (h *harness) startUpstreamLogin(t *testing.T) (state string, cookie *http.Cookie) {
	t.Helper()
	resp := h.get(t, "/auth", authQuery())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth = %d, want a 302 to Telegram; body=%s", resp.StatusCode, body(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.Name == bindingCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("GET /auth set no binding cookie")
	}
	return loc.Query().Get("state"), cookie
}

func (h *harness) returnFromTelegram(t *testing.T, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.URL+"/callback?"+url.Values{
		"code": {"telegram-code"}, "state": {state},
	}.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
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

func TestTelegramFlowEndToEnd(t *testing.T) {
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321, Name: "Пётр Кузнецов", Username: "petr"}}
	h := newTelegramHarness(t, up)

	state, cookie := h.startUpstreamLogin(t)
	if up.callback != "https://broker.example.com/callback" {
		t.Errorf("broker offered Telegram the callback %q; it must be the one address registered in BotFather", up.callback)
	}

	resp := h.returnFromTelegram(t, state, cookie)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /callback = %d, want 302; body=%s", resp.StatusCode, body(t, resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "app-state-value" {
		t.Errorf("state = %q, want the application's own state", loc.Query().Get("state"))
	}

	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code came back to the application")
	}
	if tokenResp := h.postToken(t, tokenForm(code)); tokenResp.StatusCode != http.StatusOK {
		t.Errorf("POST /token = %d; body=%s", tokenResp.StatusCode, body(t, tokenResp))
	}
}

func TestBrokerUsesItsOwnPKCEPairUpstream(t *testing.T) {
	// The broker is a client of Telegram and a provider to the application. The
	// two PKCE pairs are unrelated, and mixing them up would be invisible until
	// Telegram started refusing exchanges.
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321}}
	h := newTelegramHarness(t, up)

	state, cookie := h.startUpstreamLogin(t)
	h.returnFromTelegram(t, state, cookie)

	if up.verifier == "" || up.challenge == "" {
		t.Fatal("the broker sent no PKCE pair upstream")
	}
	if oidc.S256Challenge(up.verifier) != up.challenge {
		t.Error("the verifier the broker sent to /token does not match the challenge it sent to /auth")
	}
	if up.challenge == challenge {
		t.Error("the broker forwarded the application's own code_challenge upstream instead of making its own")
	}
}

func TestCallbackNeedsTheBindingCookie(t *testing.T) {
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321}}
	h := newTelegramHarness(t, up)

	state, _ := h.startUpstreamLogin(t)
	if resp := h.returnFromTelegram(t, state, nil); resp.StatusCode == http.StatusFound {
		t.Error("GET /callback completed a login with no binding cookie: this is login-CSRF")
	}
}

func TestCallbackRejectsAnUnknownState(t *testing.T) {
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321}}
	h := newTelegramHarness(t, up)

	_, cookie := h.startUpstreamLogin(t)
	if resp := h.returnFromTelegram(t, "state-nobody-issued", cookie); resp.StatusCode == http.StatusFound {
		t.Error("GET /callback honoured a state the broker never issued")
	}
}

func TestCallbackSurfacesAnUpstreamFailure(t *testing.T) {
	up := &stubUpstream{err: errors.New("telegram said no")}
	h := newTelegramHarness(t, up)

	state, cookie := h.startUpstreamLogin(t)
	resp := h.returnFromTelegram(t, state, cookie)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("GET /callback = %d, want 502 when the exchange fails", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("the failure carried Location %q", loc)
	}
}

func TestRefusedIDIsStoppedInTelegramModeToo(t *testing.T) {
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321}}
	h := newHarness(t, func(o *Options) {
		o.Config.MockEnabled = false
		o.Config.MockUsers = nil
		o.Upstream = up
		o.Config.AllowedTelegramIDs = []int64{111222333}
	})

	state, cookie := h.startUpstreamLogin(t)
	if resp := h.returnFromTelegram(t, state, cookie); resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET /callback = %d, want 403 for an id outside the allow list", resp.StatusCode)
	}
}

func TestTheTwoModesDoNotExposeEachOthersEndpoints(t *testing.T) {
	up := &stubUpstream{identity: oidc.Identity{ID: 987654321}}
	tg := newTelegramHarness(t, up)
	if resp := tg.selectUser(t, "any", nil, "987654321"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /auth/select = %d in telegram mode, want 404", resp.StatusCode)
	}

	mock := newHarness(t, nil)
	if resp := mock.get(t, "/callback", url.Values{"code": {"c"}, "state": {"s"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /callback = %d in mock mode, want 404", resp.StatusCode)
	}
}

func TestTwoApplicationsLogInSideBySideWithoutTouchingTheBroker(t *testing.T) {
	// The headline requirement: two projects on two ports, one broker, nothing
	// reconfigured between them.
	h := newHarness(t, nil)

	first := authQuery()
	first.Set("redirect_uri", "http://127.0.0.1:8080/auth/telegram/callback")
	second := authQuery()
	second.Set("client_id", "web-app")
	second.Set("redirect_uri", "http://localhost:8081/auth/callback")

	for _, q := range []url.Values{first, second} {
		flow, cookie := h.startLogin(t, q)
		resp := h.selectUser(t, flow, cookie, "987654321")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("login for %s = %d", q.Get("redirect_uri"), resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if got := loc.Scheme + "://" + loc.Host + loc.Path; got != q.Get("redirect_uri") {
			t.Errorf("landed at %s, want %s", got, q.Get("redirect_uri"))
		}
	}
}
