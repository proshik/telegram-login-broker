package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

var (
	// ErrUnsupportedAlg means the key names an algorithm this build cannot
	// verify. It is a refusal, never a reason to skip verification.
	ErrUnsupportedAlg = errors.New("unsupported signing algorithm")
	// ErrVerify covers every other reason an upstream token was not accepted.
	ErrVerify = errors.New("id_token verification failed")
)

// KeySet caches the upstream JWKS and verifies tokens against it.
//
// The document lives at https://oauth.telegram.org/.well-known/jwks.json and
// currently holds four keys: RS256, ES256, EdDSA and ES256K. The algorithm a
// bot signs with is chosen in BotFather and defaults to RS256.
type KeySet struct {
	mu   sync.Mutex
	keys map[string]jwk

	fetch      func(context.Context) ([]byte, error)
	now        func() time.Time
	minRefetch time.Duration

	loaded      bool
	lastRefetch time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func NewKeySet(fetch func(context.Context) ([]byte, error), now func() time.Time, minRefetch time.Duration) *KeySet {
	return &KeySet{
		keys:       make(map[string]jwk),
		fetch:      fetch,
		now:        now,
		minRefetch: minRefetch,
	}
}

// Verify checks the signature of an upstream id_token and returns its claims.
// It does not judge iss, aud or exp — that belongs to the caller, which knows
// what it asked for.
func (k *KeySet) Verify(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token has %d segments, want 3", ErrVerify, len(parts))
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not raw base64url", ErrVerify)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON", ErrVerify)
	}

	// "none" is refused here, before any key lookup and therefore before any
	// chance to make the broker fetch something on an attacker's behalf.
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return nil, fmt.Errorf("%w: header alg %q", ErrVerify, header.Alg)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("%w: header has no kid", ErrVerify)
	}

	key, err := k.keyFor(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	// The algorithm comes from the key. Reading it from the header is what turns
	// a public modulus into an HMAC secret.
	alg := key.algorithm()
	if !strings.EqualFold(header.Alg, alg) {
		return nil, fmt.Errorf("%w: header claims %s but key %s is %s", ErrVerify, header.Alg, key.Kid, alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not raw base64url", ErrVerify)
	}
	if err := key.verify(parts[0]+"."+parts[1], sig, alg); err != nil {
		return nil, err
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not raw base64url", ErrVerify)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not JSON", ErrVerify)
	}
	return claims, nil
}

// keyFor returns the key for kid, loading the document on first use and
// refetching at most once per cooldown when the kid is unknown. Without that
// cooldown a stream of made-up kids turns the broker into an amplifier pointed
// at Telegram.
func (k *KeySet) keyFor(ctx context.Context, kid string) (jwk, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.loaded {
		if err := k.reloadLocked(ctx); err != nil {
			return jwk{}, err
		}
		k.loaded = true
	}
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}

	now := k.now()
	if !k.lastRefetch.IsZero() && now.Sub(k.lastRefetch) < k.minRefetch {
		return jwk{}, fmt.Errorf("%w: unknown kid %q and the refetch cooldown has not elapsed", ErrVerify, kid)
	}
	k.lastRefetch = now
	if err := k.reloadLocked(ctx); err != nil {
		return jwk{}, err
	}
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return jwk{}, fmt.Errorf("%w: unknown kid %q", ErrVerify, kid)
}

func (k *KeySet) reloadLocked(ctx context.Context) error {
	raw, err := k.fetch(ctx)
	if err != nil {
		return fmt.Errorf("%w: fetching JWKS: %v", ErrVerify, err)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%w: JWKS is not JSON: %v", ErrVerify, err)
	}
	fresh := make(map[string]jwk, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kid != "" {
			fresh[key.Kid] = key
		}
	}
	k.keys = fresh
	return nil
}

// algorithm reports what the key itself says it is, falling back to the shape of
// the key when the JWKS omits alg.
func (j jwk) algorithm() string {
	if j.Alg != "" {
		return j.Alg
	}
	switch {
	case j.Kty == "RSA":
		return "RS256"
	case j.Kty == "EC" && j.Crv == "P-256":
		return "ES256"
	case j.Kty == "EC" && j.Crv == "secp256k1":
		return "ES256K"
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		return "EdDSA"
	}
	return ""
}

func (j jwk) verify(signingInput string, sig []byte, alg string) error {
	switch alg {
	case "RS256":
		pub, err := j.rsaKey()
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("%w: bad RS256 signature", ErrVerify)
		}
		return nil

	case "ES256":
		pub, err := j.ecKey()
		if err != nil {
			return err
		}
		if len(sig) != 64 {
			return fmt.Errorf("%w: ES256 signature is %d bytes, want 64", ErrVerify, len(sig))
		}
		digest := sha256.Sum256([]byte(signingInput))
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("%w: bad ES256 signature", ErrVerify)
		}
		return nil

	case "EdDSA":
		raw, err := decodeB64(j.X)
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: Ed25519 key is %d bytes", ErrVerify, len(raw))
		}
		if !ed25519.Verify(ed25519.PublicKey(raw), []byte(signingInput), sig) {
			return fmt.Errorf("%w: bad EdDSA signature", ErrVerify)
		}
		return nil

	case "ES256K":
		// secp256k1 is not in the Go standard library. Telegram offers it only
		// when a bot is switched to it by hand in BotFather, and restricts it to
		// the bare openid scope — but silently letting an unverified token
		// through would be far worse than refusing to start this login.
		return fmt.Errorf("%w: ES256K (secp256k1) is not in the Go standard library", ErrUnsupportedAlg)

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
	}
}

func (j jwk) rsaKey() (*rsa.PublicKey, error) {
	n, err := decodeB64(j.N)
	if err != nil {
		return nil, err
	}
	e, err := decodeB64(j.E)
	if err != nil {
		return nil, err
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, fmt.Errorf("%w: RSA key is missing n or e", ErrVerify)
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() > 1<<31-1 {
		return nil, fmt.Errorf("%w: implausible RSA exponent", ErrVerify)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}

func (j jwk) ecKey() (*ecdsa.PublicKey, error) {
	x, err := decodeB64(j.X)
	if err != nil {
		return nil, err
	}
	y, err := decodeB64(j.Y)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates must be 32 bytes each", ErrVerify)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func decodeB64(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS field is not raw base64url", ErrVerify)
	}
	return raw, nil
}
