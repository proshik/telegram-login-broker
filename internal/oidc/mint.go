package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Signer mints the broker's own id_tokens.
//
// ES256 rather than RS256 because generating an ephemeral key has to be
// instant — an RSA-2048 keygen would put a visible pause in every start — and
// because P-256 is supported everywhere.
type Signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
	ttl    time.Duration
	now    func() time.Time
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func NewSigner(key *ecdsa.PrivateKey, issuer string, ttl time.Duration, now func() time.Time) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key must be on P-256 for ES256")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer is empty")
	}
	kid, err := thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, kid: kid, issuer: issuer, ttl: ttl, now: now}, nil
}

func (s *Signer) KeyID() string               { return s.kid }
func (s *Signer) Issuer() string              { return s.issuer }
func (s *Signer) PublicKey() crypto.PublicKey { return &s.key.PublicKey }

// MintIDToken produces the id_token for one successful login. aud is the
// client_id the application sent, echoed back: it is the application's own id,
// never the broker's id at Telegram.
func (s *Signer) MintIDToken(aud string, id Identity) (string, error) {
	now := s.now()
	header := map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid}

	// A map, not a struct, so that empty optional claims are omitted rather than
	// emitted as "". aud stays a string: as an array it silently turns the
	// audience check off in both consumers.
	claims := map[string]any{
		"iss": s.issuer,
		"aud": aud,
		"sub": fmt.Sprintf("%d", id.ID),
		"id":  id.ID,
		"iat": now.Unix(),
		"exp": now.Add(s.ttl).Unix(),
	}
	if id.Name != "" {
		claims["name"] = id.Name
	}
	if id.Username != "" {
		claims["preferred_username"] = id.Username
	}
	if id.PhotoURL != "" {
		claims["picture"] = id.PhotoURL
	}

	signingInput, err := encodeSegment(header)
	if err != nil {
		return "", err
	}
	payload, err := encodeSegment(claims)
	if err != nil {
		return "", err
	}
	signingInput += "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}
	// JOSE wants fixed-width r||s, not the ASN.1 sequence crypto/ecdsa hands out
	// by default. ASN.1 here verifies fine in Go and is rejected by every JWT
	// library.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWKS is the broker's public key set. The consumers do not check the signature
// today, so nothing depends on this yet; the broker signs honestly anyway, so
// that phase 2 can turn verification on without touching the broker.
func (s *Signer) JWKS() ([]byte, error) {
	pub := &s.key.PublicKey
	size := (pub.Curve.Params().BitSize + 7) / 8
	doc := map[string]any{"keys": []any{map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"kid": s.kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
	}}}
	return json.Marshal(doc)
}

// thumbprint is the RFC 7638 JWK thumbprint: the SHA-256 of the required
// members in lexicographic order, with no whitespace. Deriving the kid from the
// key means it changes exactly when the key does.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	size := (pub.Curve.Params().BitSize + 7) / 8
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(new(big.Int).Set(pub.X).FillBytes(make([]byte, size))),
		base64.RawURLEncoding.EncodeToString(new(big.Int).Set(pub.Y).FillBytes(make([]byte, size))),
	)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func encodeSegment(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	// RawURLEncoding, never StdEncoding: a single "=" makes the token undecodable
	// in go-app while still working in kotlin-app.
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
