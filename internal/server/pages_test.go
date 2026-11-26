package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// directive returns the source list of one CSP directive, or nil if absent.
func directive(t *testing.T, policy, name string) []string {
	t.Helper()
	if strings.Contains(policy, ",") {
		t.Fatalf("CSP %q holds more than one policy", policy)
	}
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) > 0 && fields[0] == name {
			return fields[1:]
		}
	}
	return nil
}

// Chrome applies form-action to every redirect that follows a form submission,
// so the chooser's POST, answered with a 302 to the application, is blocked
// unless the application's origin is in the list. 'self' alone left the browser
// stuck on the chooser.
func TestChooserFormActionAllowsTheRedirectOrigin(t *testing.T) {
	h := newHarness(t, nil)
	cases := map[string]struct {
		clientID, redirectURI, want string
	}{
		"loopback":       {appClientID, appRedirect, "http://localhost:8080"},
		"listed origin":  {"web-app", "https://web-app.example.com/auth/cb?x=1", "https://web-app.example.com"},
		"uppercase host": {appClientID, "HTTP://LOCALHOST:8080/cb", "http://localhost:8080"},
	}
	for name, c := range cases {
		q := authQuery()
		q.Set("client_id", c.clientID)
		q.Set("redirect_uri", c.redirectURI)
		resp := h.get(t, "/auth", q)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: GET /auth = %d, want 200", name, resp.StatusCode)
		}
		policy := resp.Header.Get("Content-Security-Policy")
		got := directive(t, policy, "form-action")
		if strings.Join(got, " ") != "'self' "+c.want {
			t.Errorf("%s: form-action = %q, want exactly 'self' and %s", name, got, c.want)
		}
		if d := directive(t, policy, "default-src"); strings.Join(d, " ") != "'none'" {
			t.Errorf("%s: default-src = %q, want 'none'", name, d)
		}
	}
}

// Pages without a form that leads off-site keep form-action at 'self'.
func TestOtherPagesKeepFormActionSelf(t *testing.T) {
	h := newHarness(t, nil)
	q := authQuery()
	q.Set("redirect_uri", "https://evil.example.com/cb")
	for name, resp := range map[string]*http.Response{
		"refusal": h.get(t, "/auth", q),
		"index":   h.get(t, "/", nil),
	} {
		got := directive(t, resp.Header.Get("Content-Security-Policy"), "form-action")
		if strings.Join(got, " ") != "'self'" {
			t.Errorf("%s: form-action = %q, want only 'self'", name, got)
		}
	}
}

// A host that survives url.Parse and the loopback check but carries CSP
// separators must not reach the header, where it would add directives or a
// second policy.
func TestFormActionSourceRefusesSeparators(t *testing.T) {
	for _, raw := range []string{
		"http://a;sandbox.localhost:8080/cb",
		"http://a,b.localhost:8080/cb",
		"http://a'b.localhost:8080/cb",
	} {
		if _, err := url.Parse(raw); err != nil {
			continue // rejected earlier anyway
		}
		if got := formActionSource(raw); got != "" {
			t.Errorf("formActionSource(%q) = %q, want empty", raw, got)
		}
	}
}
