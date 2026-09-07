// Package upstream talks to the real Telegram OIDC provider.
//
// The flow is documented at core.telegram.org/widgets/login: authorization code
// with PKCE against oauth.telegram.org, and an id_token signed with a key from
// its JWKS. The algorithm is a property of the bot, chosen in BotFather, and
// defaults to RS256.
package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/proshik/telegram-login-broker/internal/oidc"
	"github.com/proshik/telegram-login-broker/internal/registry"
)

const DefaultBaseURL = "https://oauth.telegram.org"

type Telegram struct {
	base   string
	http   *http.Client
	keys   *oidc.KeySet
	verify bool
	now    func() time.Time

	logger      *slog.Logger
	logClaimSet sync.Once
}

func New(baseURL string, hc *http.Client, verify bool, now func() time.Time) *Telegram {
	base := strings.TrimRight(baseURL, "/")
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	t := &Telegram{base: base, http: hc, verify: verify, now: now, logger: slog.Default()}
	t.keys = oidc.NewKeySet(t.fetchJWKS, now, 5*time.Minute)
	return t
}

func (t *Telegram) SetLogger(l *slog.Logger) {
	if l != nil {
		t.logger = l
	}
}

// AuthURL is where the browser goes. Only the bot's public client_id travels
// here; the secret stays on the broker and is used server-to-server.
func (t *Telegram) AuthURL(bot registry.Bot, callbackURL, state, codeChallenge string) string {
	q := url.Values{
		"client_id":             {bot.ClientID},
		"redirect_uri":          {callbackURL},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return t.base + "/auth?" + q.Encode()
}

// Exchange trades the code for an id_token and reads the identity out of it.
func (t *Telegram) Exchange(ctx context.Context, bot registry.Bot, code, codeVerifier, callbackURL string) (oidc.Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {bot.ClientID},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return oidc.Identity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic, which is what the documentation specifies. The
	// discovery document also offers client_secret_post; sending it both ways
	// would only widen where the secret can be logged.
	req.SetBasicAuth(bot.ClientID, bot.ClientSecret)

	resp, err := t.http.Do(req)
	if err != nil {
		return oidc.Identity{}, fmt.Errorf("token request to Telegram: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return oidc.Identity{}, fmt.Errorf("reading Telegram's token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return oidc.Identity{}, fmt.Errorf("Telegram token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	// Telegram returns four keys — expires_in as well — so decode only what is
	// needed and ignore the rest.
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return oidc.Identity{}, fmt.Errorf("Telegram's token response is not JSON: %w", err)
	}
	if payload.IDToken == "" {
		return oidc.Identity{}, fmt.Errorf("Telegram returned no id_token")
	}
	return t.identityFrom(ctx, payload.IDToken)
}

func (t *Telegram) identityFrom(ctx context.Context, idToken string) (oidc.Identity, error) {
	var claims map[string]any
	var err error
	if t.verify {
		claims, err = t.keys.Verify(ctx, idToken)
		if err != nil {
			return oidc.Identity{}, err
		}
	} else {
		// Only reachable through BROKER_VERIFY_ID_TOKEN=false, which exists so
		// that an upstream change (a new algorithm, say) cannot lock the owner
		// out. It has to be switched on by hand, and it says what it does.
		claims, err = unverifiedClaims(idToken)
		if err != nil {
			return oidc.Identity{}, err
		}
	}

	// Which claims Telegram actually sends is the thing to know before anyone
	// makes them mandatory downstream: `id` is documented in prose but absent
	// from claims_supported, so only a real login settles it. Names only, sorted,
	// once per process — the values are the person who just logged in.
	t.logClaimSet.Do(func() {
		t.logger.Info("upstream id_token claim set",
			"claims", strings.Join(slices.Sorted(maps.Keys(claims)), ","),
			"verified", t.verify)
	})

	if iss, _ := claims["iss"].(string); iss != t.base {
		return oidc.Identity{}, fmt.Errorf("id_token iss is %q, want %q", iss, t.base)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return oidc.Identity{}, fmt.Errorf("id_token has no exp")
	}
	if !t.now().Before(time.Unix(int64(exp), 0)) {
		return oidc.Identity{}, fmt.Errorf("id_token expired at %s", time.Unix(int64(exp), 0))
	}

	// The Telegram id lives in the non-standard "id" claim. It is documented in
	// prose but absent from claims_supported, so it is read strictly and never
	// substituted: sub is a different number, and standing it in would hand back
	// a stable, plausible and wrong person.
	id, err := claimInt64(claims["id"])
	if err != nil {
		return oidc.Identity{}, fmt.Errorf("id_token claim \"id\": %w", err)
	}
	identity := oidc.Identity{ID: id}
	identity.Name, _ = claims["name"].(string)
	identity.Username, _ = claims["preferred_username"].(string)
	identity.PhotoURL, _ = claims["picture"].(string)
	return identity, nil
}

func claimInt64(v any) (int64, error) {
	switch t := v.(type) {
	case nil:
		return 0, fmt.Errorf("missing")
	case float64:
		return int64(t), nil
	case string:
		id, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a Telegram id", t)
		}
		return id, nil
	default:
		return 0, fmt.Errorf("is a %T, want a number or a numeric string", v)
	}
}

func (t *Telegram) fetchJWKS(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
