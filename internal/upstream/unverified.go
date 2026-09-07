package upstream

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// unverifiedClaims reads the payload without checking anything. It is kept in a
// file of its own, under a name that cannot be mistaken for something safe, so
// that it is obvious in review when a call to it appears anywhere else.
func unverifiedClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token payload is not raw base64url: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("id_token payload is not JSON: %w", err)
	}
	return claims, nil
}
