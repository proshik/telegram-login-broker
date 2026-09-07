package oidc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() = %v", err)
	}
	fixed := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s, err := NewSigner(key, "https://broker.example.com", time.Hour, func() time.Time { return fixed })
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}
	return s
}

func testIdentity() Identity {
	return Identity{
		ID:       987654321,
		Name:     "Пётр Кузнецов",
		Username: "petr",
		PhotoURL: "https://cdn4.telesco.pe/file/photo.jpg",
	}
}

// decodeSegment mirrors Go's strict RawURLEncoding, which is what go-app uses.
// A token carrying padding decodes in Java and fails here — the asymmetry that
// makes such a bug look like "go-app is broken".
func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("segment %q is not raw base64url: %v", seg, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("segment is not JSON: %v", err)
	}
	return m
}

func TestMintIDTokenHasThreeUnpaddedSegments(t *testing.T) {
	tok, err := testSigner(t).MintIDToken("kotlin-app", testIdentity())
	if err != nil {
		t.Fatalf("MintIDToken() = %v", err)
	}
	if strings.Contains(tok, "=") {
		t.Errorf("token carries base64 padding, which Go's RawURLEncoding refuses: %q", tok)
	}
	if got := len(strings.Split(tok, ".")); got != 3 {
		t.Errorf("token has %d segments, want 3", got)
	}
}

func TestMintIDTokenClaims(t *testing.T) {
	s := testSigner(t)
	tok, err := s.MintIDToken("kotlin-app", testIdentity())
	if err != nil {
		t.Fatalf("MintIDToken() = %v", err)
	}
	claims := decodeSegment(t, strings.Split(tok, ".")[1])

	// id is the Telegram id and arrives as a JSON number, the way real Telegram
	// sends it.
	id, ok := claims["id"].(float64)
	if !ok {
		t.Fatalf("claim id is %T, want a JSON number", claims["id"])
	}
	if int64(id) != 987654321 {
		t.Errorf("claim id = %v, want 987654321", id)
	}
	// aud must be a bare string: as an array both consumers silently skip the
	// audience check instead of failing.
	if aud, ok := claims["aud"].(string); !ok || aud != "kotlin-app" {
		t.Errorf("claim aud = %#v, want the string %q", claims["aud"], "kotlin-app")
	}
	if iss, _ := claims["iss"].(string); iss != "https://broker.example.com" {
		t.Errorf("claim iss = %v, want the broker's issuer", claims["iss"])
	}
	if name, _ := claims["name"].(string); name != "Пётр Кузнецов" {
		t.Errorf("claim name = %q, want the Cyrillic name unchanged", name)
	}
	if u, _ := claims["preferred_username"].(string); u != "petr" {
		t.Errorf("claim preferred_username = %v, want petr", claims["preferred_username"])
	}
	if p, _ := claims["picture"].(string); p != "https://cdn4.telesco.pe/file/photo.jpg" {
		t.Errorf("claim picture = %v", claims["picture"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("claim exp is %T, want a JSON number", claims["exp"])
	}
	wantExp := float64(time.Date(2026, 9, 7, 13, 0, 0, 0, time.UTC).Unix())
	if exp != wantExp {
		t.Errorf("claim exp = %v, want %v (now + ttl)", exp, wantExp)
	}
	if iat, ok := claims["iat"].(float64); !ok || iat != wantExp-3600 {
		t.Errorf("claim iat = %v, want %v", claims["iat"], wantExp-3600)
	}
}

func TestMintIDTokenIssuerCarriesNoTelegramSubstring(t *testing.T) {
	// Naming the issuer so that the consumers' `iss contains "telegram"` check
	// passes would make substituting the broker for real Telegram silent. It has
	// to fail loudly instead.
	s := testSigner(t)
	tok, _ := s.MintIDToken("kotlin-app", testIdentity())
	claims := decodeSegment(t, strings.Split(tok, ".")[1])
	if iss, _ := claims["iss"].(string); strings.Contains(strings.ToLower(iss), "telegram") {
		t.Errorf("issuer %q contains \"telegram\"", iss)
	}
}

func TestMintIDTokenHeaderNamesES256AndTheSigningKey(t *testing.T) {
	s := testSigner(t)
	tok, _ := s.MintIDToken("kotlin-app", testIdentity())
	header := decodeSegment(t, strings.Split(tok, ".")[0])

	if alg, _ := header["alg"].(string); alg != "ES256" {
		t.Errorf("header alg = %v, want ES256", header["alg"])
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("header typ = %v, want JWT", header["typ"])
	}
	if kid, _ := header["kid"].(string); kid != s.KeyID() {
		t.Errorf("header kid = %v, want %v", header["kid"], s.KeyID())
	}
}

func TestMintIDTokenSignatureIsJOSERawNotASN1(t *testing.T) {
	// JOSE wants r||s, each padded to the curve size. An ASN.1 signature verifies
	// with crypto/ecdsa but is rejected by every JWT library there is.
	s := testSigner(t)
	tok, _ := s.MintIDToken("kotlin-app", testIdentity())
	parts := strings.Split(tok, ".")

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not raw base64url: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (r||s for P-256)", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	sv := new(big.Int).SetBytes(sig[32:])
	pub, ok := s.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey() is %T, want *ecdsa.PublicKey", s.PublicKey())
	}
	if !ecdsa.Verify(pub, digest[:], r, sv) {
		t.Error("signature does not verify against the signer's public key")
	}
}

func TestJWKSPublishesTheSigningKeyAndNoSecret(t *testing.T) {
	s := testSigner(t)
	raw, err := s.JWKS()
	if err != nil {
		t.Fatalf("JWKS() = %v", err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("JWKS is not JSON: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	for field, want := range map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig"} {
		if got, _ := k[field].(string); got != want {
			t.Errorf("JWKS key %s = %v, want %v", field, k[field], want)
		}
	}
	if kid, _ := k["kid"].(string); kid != s.KeyID() {
		t.Errorf("JWKS kid = %v, want %v", k["kid"], s.KeyID())
	}
	if _, present := k["d"]; present {
		t.Error("JWKS leaks the private scalar d")
	}
}

func TestKeyIDIsTheRFC7638ThumbprintSoDistinctKeysDiffer(t *testing.T) {
	a, b := testSigner(t), testSigner(t)
	if a.KeyID() == b.KeyID() {
		t.Error("two independently generated keys share a kid")
	}
	if len(a.KeyID()) != 43 {
		t.Errorf("kid is %d characters, want 43 (base64url SHA-256)", len(a.KeyID()))
	}
}
