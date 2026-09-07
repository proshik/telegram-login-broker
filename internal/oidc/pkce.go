package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrPKCE is returned when a code_verifier does not produce the code_challenge
// that was pinned to the pending authorization.
var ErrPKCE = errors.New("pkce verification failed")

// challengeLen is the length of a base64url-encoded SHA-256 digest without
// padding. S256 challenges are always exactly this long.
const challengeLen = 43

// S256Challenge derives the code_challenge for a verifier, per RFC 7636 §4.2.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a code_verifier against the stored challenge. Only the S256
// method exists here: "plain" is never accepted, so a client cannot downgrade
// itself by sending its verifier as the challenge.
func VerifyPKCE(challenge, verifier string) error {
	want := S256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) != 1 {
		return ErrPKCE
	}
	return nil
}

// ValidateChallengeFormat rejects anything that cannot be an S256 challenge
// before it reaches the store, which keeps malformed input out of memory and
// makes the later comparison meaningful.
func ValidateChallengeFormat(challenge string) error {
	if len(challenge) != challengeLen {
		return fmt.Errorf("%w: code_challenge must be %d characters, got %d", ErrPKCE, challengeLen, len(challenge))
	}
	for i := 0; i < len(challenge); i++ {
		c := challenge[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return fmt.Errorf("%w: code_challenge is not base64url", ErrPKCE)
		}
	}
	return nil
}
