package registry

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// encPrefix marks a field as sealed. It keeps the file self-describing: anyone
// reading it by eye can tell a secret from a name.
const encPrefix = "enc:"

// Box seals the secrets in the registry file with AES-GCM under a key from the
// environment. It matters more than it looks: deploy platforms commonly keep
// application env in clear text, so the file and the key are not equally
// exposed, and a stolen file on its own is useless.
type Box struct {
	aead cipher.AEAD
}

func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("registry encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (b *Box) Open(sealed string) (string, error) {
	if !strings.HasPrefix(sealed, encPrefix) {
		return "", fmt.Errorf("registry field is not sealed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, encPrefix))
	if err != nil {
		return "", fmt.Errorf("sealed registry field is not base64: %w", err)
	}
	if len(raw) < b.aead.NonceSize() {
		return "", fmt.Errorf("sealed registry field is truncated")
	}
	nonce, ct := raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():]
	plain, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt registry field: wrong key or tampered file")
	}
	return string(plain), nil
}
