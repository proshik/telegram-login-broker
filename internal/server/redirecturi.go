package server

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// ErrRedirectURI is the sentinel behind every refusal below. A caller that sees
// it must render its own error page: the whole point of these checks is that the
// URI is not trustworthy, so it must never appear in a Location header.
var ErrRedirectURI = errors.New("redirect_uri rejected")

// CheckRedirectURI decides whether the browser may be sent to raw once the login
// finishes. It accepts any loopback address on any port — that is what frees a
// developer from touching BotFather for every new project — plus the exact
// origins the client registered in allowedOrigins.
//
// The order of the checks matters and is not a matter of taste; see the comments.
func CheckRedirectURI(raw string, allowedOrigins []string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: unparseable", ErrRedirectURI)
	}
	// Without IsAbs a scheme-relative "//evil.com/cb" would sail through, since
	// url.Parse reads it as a perfectly valid host-bearing reference.
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: not an absolute URI with a host", ErrRedirectURI)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", ErrRedirectURI, u.Scheme)
	}
	// "http://localhost@evil.com/cb" parses with userinfo "localhost" and host
	// "evil.com". Any check written as strings.HasPrefix(raw, "http://localhost")
	// hands the authorization code to evil.com.
	if u.User != nil {
		return fmt.Errorf("%w: userinfo present", ErrRedirectURI)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: fragment present", ErrRedirectURI) // RFC 6749 §3.1.2
	}

	// Go does not case-fold the host, so "HTTP://LOCALHOST:8080" would not match
	// the literal "localhost" below.
	host := strings.ToLower(u.Hostname())
	if isLoopbackHost(host) {
		return nil
	}

	origin := u.Scheme + "://" + strings.ToLower(u.Host)
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: origin %s is neither loopback nor allow-listed", ErrRedirectURI, origin)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Deliberately strict: ParseAddr refuses "127.1", "0177.0.0.1" and
		// "2130706433". An honest client never writes an address that way, and
		// each of those forms is a known way past a naive parser.
		return false
	}
	// Unmap matters: without it ::ffff:127.0.0.1 is not reported as loopback.
	return addr.Unmap().IsLoopback()
}
