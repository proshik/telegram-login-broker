package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signingInput(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64(h) + "." + b64(c)
}

func assemble(input string, sig []byte) string { return input + "." + b64(sig) }

type upstreamKeys struct {
	rsa   *rsa.PrivateKey
	ec    *ecdsa.PrivateKey
	edPub ed25519.PublicKey
	edKey ed25519.PrivateKey
}

func newUpstreamKeys(t *testing.T) *upstreamKeys {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &upstreamKeys{rsa: rk, ec: ek, edPub: pub, edKey: priv}
}

// jwks mirrors the shape of the real document at oauth.telegram.org: four keys,
// one per algorithm, including the secp256k1 one Go cannot verify.
func (k *upstreamKeys) jwks() []byte {
	size := 32
	doc := map[string]any{"keys": []any{
		map[string]string{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "oidc-1",
			"n": b64(k.rsa.N.Bytes()),
			"e": b64(big.NewInt(int64(k.rsa.E)).Bytes()),
		},
		map[string]string{
			"kty": "EC", "alg": "ES256", "crv": "P-256", "use": "sig", "kid": "oidc-es256-1",
			"x": b64(k.ec.X.FillBytes(make([]byte, size))),
			"y": b64(k.ec.Y.FillBytes(make([]byte, size))),
		},
		map[string]string{
			"kty": "OKP", "alg": "EdDSA", "crv": "Ed25519", "use": "sig", "kid": "oidc-eddsa-1",
			"x": b64(k.edPub),
		},
		map[string]string{
			"kty": "EC", "alg": "ES256K", "crv": "secp256k1", "use": "sig", "kid": "oidc-es256k-1",
			"x": b64(make([]byte, 32)),
			"y": b64(make([]byte, 32)),
		},
	}}
	raw, _ := json.Marshal(doc)
	return raw
}

func (k *upstreamKeys) signRS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	in := signingInput(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "oidc-1"}, claims)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return assemble(in, sig)
}

func (k *upstreamKeys) signES256(t *testing.T, claims map[string]any) string {
	t.Helper()
	in := signingInput(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "oidc-es256-1"}, claims)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k.ec, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return assemble(in, sig)
}

func (k *upstreamKeys) signEdDSA(t *testing.T, claims map[string]any) string {
	t.Helper()
	in := signingInput(t, map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "oidc-eddsa-1"}, claims)
	return assemble(in, ed25519.Sign(k.edKey, []byte(in)))
}

type countingFetcher struct {
	mu    sync.Mutex
	body  []byte
	calls int
}

func (f *countingFetcher) fetch(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.body, nil
}

func (f *countingFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func upstreamClaims() map[string]any {
	return map[string]any{
		"iss": "https://oauth.telegram.org",
		"aud": "123456789",
		"sub": "1234123412341234123",
		"id":  987654321,
		"exp": time.Date(2026, 9, 7, 13, 0, 0, 0, time.UTC).Unix(),
	}
}

func newTestKeySet(t *testing.T, f *countingFetcher, clk *fakeVerifyClock) *KeySet {
	t.Helper()
	return NewKeySet(f.fetch, clk.now, 5*time.Minute)
}

type fakeVerifyClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeVerifyClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeVerifyClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newVerifyClock() *fakeVerifyClock {
	return &fakeVerifyClock{t: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)}
}

// --- tests -------------------------------------------------------------------

func TestKeySetVerifiesEveryAlgorithmGoCanDo(t *testing.T) {
	k := newUpstreamKeys(t)
	f := &countingFetcher{body: k.jwks()}
	ks := newTestKeySet(t, f, newVerifyClock())

	for name, token := range map[string]string{
		"RS256": k.signRS256(t, upstreamClaims()),
		"ES256": k.signES256(t, upstreamClaims()),
		"EdDSA": k.signEdDSA(t, upstreamClaims()),
	} {
		claims, err := ks.Verify(context.Background(), token)
		if err != nil {
			t.Errorf("Verify(%s) = %v, want nil", name, err)
			continue
		}
		if got, _ := claims["sub"].(string); got != "1234123412341234123" {
			t.Errorf("Verify(%s) returned claims %v", name, claims)
		}
	}
}

func TestKeySetRejectsAlgNoneBeforeAnyLookup(t *testing.T) {
	k := newUpstreamKeys(t)
	f := &countingFetcher{body: k.jwks()}
	ks := newTestKeySet(t, f, newVerifyClock())

	// A real kid, so the only thing standing between this token and acceptance
	// is the refusal to honour "none".
	in := signingInput(t, map[string]any{"alg": "none", "typ": "JWT", "kid": "oidc-1"}, upstreamClaims())
	if _, err := ks.Verify(context.Background(), in+"."); err == nil {
		t.Fatal("Verify() accepted alg:none")
	}
	if f.count() != 0 {
		t.Errorf("alg:none caused %d JWKS fetches, want 0 — it must be refused before any lookup", f.count())
	}
}

func TestKeySetRejectsAlgorithmConfusion(t *testing.T) {
	// The classic: claim HS256 in the header and sign with HMAC keyed on the RSA
	// modulus, which is public. Taking alg from the header would accept this.
	k := newUpstreamKeys(t)
	ks := newTestKeySet(t, &countingFetcher{body: k.jwks()}, newVerifyClock())

	in := signingInput(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": "oidc-1"}, upstreamClaims())
	mac := hmac.New(sha256.New, k.rsa.N.Bytes())
	mac.Write([]byte(in))

	if _, err := ks.Verify(context.Background(), assemble(in, mac.Sum(nil))); err == nil {
		t.Fatal("Verify() accepted an HMAC signature keyed on the public modulus")
	}
}

func TestKeySetTakesAlgorithmFromTheKeyNotTheHeader(t *testing.T) {
	// Header says RS256, kid names the EC key. Trusting the header would send an
	// ECDSA signature into an RSA verifier and produce a confusing error at best.
	k := newUpstreamKeys(t)
	ks := newTestKeySet(t, &countingFetcher{body: k.jwks()}, newVerifyClock())

	genuine := k.signES256(t, upstreamClaims())
	parts := strings.Split(genuine, ".")
	lying := signingInput(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "oidc-es256-1"}, upstreamClaims())
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Verify(context.Background(), assemble(lying, sig)); err == nil {
		t.Error("Verify() accepted a token whose header algorithm disagrees with its key")
	}
}

func TestKeySetRejectsES256KAsUnsupportedRatherThanSkipping(t *testing.T) {
	k := newUpstreamKeys(t)
	ks := newTestKeySet(t, &countingFetcher{body: k.jwks()}, newVerifyClock())

	in := signingInput(t, map[string]any{"alg": "ES256K", "typ": "JWT", "kid": "oidc-es256k-1"}, upstreamClaims())
	_, err := ks.Verify(context.Background(), assemble(in, make([]byte, 64)))
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("Verify() = %v, want ErrUnsupportedAlg — secp256k1 must fail loudly, never pass", err)
	}
}

func TestKeySetRejectsTamperedPayload(t *testing.T) {
	k := newUpstreamKeys(t)
	ks := newTestKeySet(t, &countingFetcher{body: k.jwks()}, newVerifyClock())

	token := k.signES256(t, upstreamClaims())
	parts := strings.Split(token, ".")
	forged := map[string]any{"iss": "https://oauth.telegram.org", "id": 111}
	raw, _ := json.Marshal(forged)
	if _, err := ks.Verify(context.Background(), parts[0]+"."+b64(raw)+"."+parts[2]); err == nil {
		t.Error("Verify() accepted a token whose payload was swapped")
	}
}

func TestUnknownKidRefetchesOnceThenIsRateLimited(t *testing.T) {
	k := newUpstreamKeys(t)
	f := &countingFetcher{body: k.jwks()}
	clk := newVerifyClock()
	ks := newTestKeySet(t, f, clk)

	// Prime the set, so the first fetch is not confused with the refetch.
	if _, err := ks.Verify(context.Background(), k.signES256(t, upstreamClaims())); err != nil {
		t.Fatal(err)
	}
	after := f.count()

	in := signingInput(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "who-is-this"}, upstreamClaims())
	unknown := assemble(in, make([]byte, 64))

	if _, err := ks.Verify(context.Background(), unknown); err == nil {
		t.Fatal("Verify() accepted a token signed by an unknown kid")
	}
	if f.count() != after+1 {
		t.Fatalf("unknown kid triggered %d fetches, want exactly 1", f.count()-after)
	}
	for range 5 {
		ks.Verify(context.Background(), unknown)
	}
	if f.count() != after+1 {
		t.Errorf("repeated unknown kids caused %d fetches — the broker is amplifying requests to Telegram", f.count()-after)
	}

	clk.advance(5*time.Minute + time.Second)
	ks.Verify(context.Background(), unknown)
	if f.count() != after+2 {
		t.Errorf("after the cooldown the set did not refetch: %d fetches", f.count()-after)
	}
}

func TestRotatedKeyIsPickedUpByTheRefetch(t *testing.T) {
	k := newUpstreamKeys(t)
	f := &countingFetcher{body: []byte(`{"keys":[]}`)}
	clk := newVerifyClock()
	ks := newTestKeySet(t, f, clk)

	token := k.signES256(t, upstreamClaims())
	if _, err := ks.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify() succeeded against an empty key set")
	}
	f.mu.Lock()
	f.body = k.jwks()
	f.mu.Unlock()

	// Rotation is picked up by the next refetch the cooldown allows, not sooner:
	// an unknown kid must never be able to drive fetches at request rate.
	clk.advance(5*time.Minute + time.Second)
	if _, err := ks.Verify(context.Background(), token); err != nil {
		t.Errorf("Verify() = %v after the key appeared upstream, want nil", err)
	}
}

func TestMalformedTokensAreRejected(t *testing.T) {
	k := newUpstreamKeys(t)
	ks := newTestKeySet(t, &countingFetcher{body: k.jwks()}, newVerifyClock())

	for name, token := range map[string]string{
		"empty":         "",
		"two segments":  "aaa.bbb",
		"four segments": "aaa.bbb.ccc.ddd",
		"not base64":    "!!!.???.***",
		"padded":        "eyJhbGciOiJFUzI1NiJ9=.e30.sig",
		"no kid":        assemble(signingInput(t, map[string]any{"alg": "ES256"}, upstreamClaims()), make([]byte, 64)),
	} {
		if _, err := ks.Verify(context.Background(), token); err == nil {
			t.Errorf("Verify(%s) = nil, want error", name)
		}
	}
}
