package server

import "testing"

func TestCheckRedirectURIAcceptsLoopback(t *testing.T) {
	accepted := []string{
		"http://[::1]:8080/cb",
		"http://127.0.0.2:8080/cb",
		"http://localhost:3000/auth/telegram/callback",
		"HTTP://LOCALHOST:8080/cb",
		"http://broker.localhost:9090/cb",
		"http://127.0.0.1/cb",
		"https://localhost:8443/cb",
	}
	for _, raw := range accepted {
		if err := CheckRedirectURI(raw, nil); err != nil {
			t.Errorf("CheckRedirectURI(%q) = %v, want nil", raw, err)
		}
	}
}

func TestCheckRedirectURIRejects(t *testing.T) {
	// Each entry is a redirect_uri that must never be honoured. The userinfo and
	// suffix cases are the ones a prefix check would let through.
	rejected := []string{
		"http://localhost@evil.com/cb",
		"http://127.0.0.1.evil.com/cb",
		"http://2130706433/cb",
		"http://0177.0.0.1/cb",
		"http://127.1/cb",
		"http://0.0.0.0:8080/cb",
		"http://[::]:8080/cb",
		"//evil.com/cb",
		"javascript:alert(1)",
		"http://localhost:8080/cb#frag",
		"ftp://localhost:8080/cb",
		"/auth/callback",
		"",
	}
	for _, raw := range rejected {
		if err := CheckRedirectURI(raw, nil); err == nil {
			t.Errorf("CheckRedirectURI(%q) = nil, want error", raw)
		}
	}
}

func TestCheckRedirectURIAllowlistMatchesOriginExactly(t *testing.T) {
	allowed := []string{"https://app.example.com", "https://other.example.com:8443"}

	if err := CheckRedirectURI("https://app.example.com/auth/callback", allowed); err != nil {
		t.Errorf("listed origin rejected: %v", err)
	}
	if err := CheckRedirectURI("https://other.example.com:8443/cb", allowed); err != nil {
		t.Errorf("listed origin with port rejected: %v", err)
	}

	// An origin is not a prefix: every one of these shares a prefix with a listed
	// entry and must still be refused.
	notAllowed := []string{
		"https://app.example.com.evil.com/cb",
		"http://app.example.com/cb",
		"https://app.example.com:8443/cb",
		"https://evil.com/cb?x=https://app.example.com",
		"https://sub.app.example.com/cb",
		"https://other.example.com/cb",
	}
	for _, raw := range notAllowed {
		if err := CheckRedirectURI(raw, allowed); err == nil {
			t.Errorf("CheckRedirectURI(%q) = nil, want error", raw)
		}
	}
}
