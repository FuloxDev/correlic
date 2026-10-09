package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	c, err := NewCipher("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"", "hunter2", strings.Repeat("x", 4096), "ünïcödé"} {
		enc, err := c.Encrypt(plain)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plain, err)
		}
		if enc == plain && plain != "" {
			t.Fatalf("ciphertext equals plaintext for %q", plain)
		}
		dec, err := c.Decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt %q: %v", plain, err)
		}
		if dec != plain {
			t.Fatalf("round trip: got %q want %q", dec, plain)
		}
	}
}

func TestNonceIsFresh(t *testing.T) {
	c, _ := NewCipher("0123456789abcdef0123456789abcdef")
	a, _ := c.Encrypt("same")
	b, _ := c.Encrypt("same")
	if a == b {
		t.Fatal("two encryptions of the same value must differ (fresh nonce)")
	}
}

func TestWrongKeyFails(t *testing.T) {
	c1, _ := NewCipher("0123456789abcdef0123456789abcdef")
	c2, _ := NewCipher("fedcba9876543210fedcba9876543210")
	enc, _ := c1.Encrypt("secret")
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatal("decrypt with the wrong key must fail")
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewCipher("short"); err == nil {
		t.Fatal("expected an error for a short key")
	}
}

func TestGarbageRejected(t *testing.T) {
	c, _ := NewCipher("0123456789abcdef0123456789abcdef")
	for _, bad := range []string{"not base64!", "AAAA", ""} {
		if _, err := c.Decrypt(bad); err == nil {
			t.Fatalf("decrypt(%q) must fail", bad)
		}
	}
}

func TestNilCipher(t *testing.T) {
	var c *Cipher
	if _, err := c.Encrypt("x"); !errors.Is(err, ErrNoCipher) {
		t.Fatalf("nil Encrypt: got %v, want ErrNoCipher", err)
	}
	if _, err := c.Decrypt("x"); !errors.Is(err, ErrNoCipher) {
		t.Fatalf("nil Decrypt: got %v, want ErrNoCipher", err)
	}
}
