package registry

import (
	"strings"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestBoxRoundTrip(t *testing.T) {
	b, err := NewBox(testKey())
	if err != nil {
		t.Fatalf("NewBox() = %v", err)
	}
	sealed, err := b.Seal("hunter2")
	if err != nil {
		t.Fatalf("Seal() = %v", err)
	}
	if strings.Contains(sealed, "hunter2") {
		t.Fatalf("Seal() left the plaintext visible: %q", sealed)
	}
	got, err := b.Open(sealed)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Open(Seal(x)) = %q, want %q", got, "hunter2")
	}
}

func TestBoxUsesAFreshNonceEachTime(t *testing.T) {
	b, _ := NewBox(testKey())
	first, _ := b.Seal("hunter2")
	second, _ := b.Seal("hunter2")
	if first == second {
		t.Error("Seal() produced identical ciphertext twice — the nonce is not fresh")
	}
}

func TestBoxRejectsTamperedCiphertext(t *testing.T) {
	b, _ := NewBox(testKey())
	sealed, _ := b.Seal("hunter2")

	tampered := []byte(sealed)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := b.Open(string(tampered)); err == nil {
		t.Error("Open() accepted tampered ciphertext")
	}
}

func TestBoxRejectsAnotherKey(t *testing.T) {
	b, _ := NewBox(testKey())
	sealed, _ := b.Seal("hunter2")

	other := testKey()
	other[0] ^= 0xff
	ob, _ := NewBox(other)
	if _, err := ob.Open(sealed); err == nil {
		t.Error("Open() decrypted with the wrong key")
	}
}

func TestNewBoxRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := NewBox(make([]byte, size)); err == nil {
			t.Errorf("NewBox(%d bytes) = nil, want error", size)
		}
	}
}
