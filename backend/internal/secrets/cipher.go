// Package secrets encrypts short secrets that must be stored at rest
// (BYOK LLM provider keys, SMTP passwords) with AES-256-GCM.
//
// One key, LLM_ENCRYPTION_KEY, protects every stored secret. The AES key is
// derived as SHA-256(LLM_ENCRYPTION_KEY) so the whole environment value
// contributes regardless of its length. Ciphertexts are base64 (standard
// encoding) of nonce || sealed bytes, the format the LLM settings store has
// used since v1.0.1, so moving it here changed nothing on disk.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// MinKeyLength is the shortest LLM_ENCRYPTION_KEY accepted. The value is
// hashed to 32 bytes, so any length works mechanically; a short value is
// still a weak key.
const MinKeyLength = 16

// ErrNoCipher is returned by the package-level helpers when no cipher is
// configured (the plane was started without LLM_ENCRYPTION_KEY).
var ErrNoCipher = errors.New("secrets: no encryption key configured")

// Cipher seals and opens secrets with one derived AES-256 key.
type Cipher struct {
	key []byte // 32 bytes
}

// NewCipher derives the AES key from envValue (normally LLM_ENCRYPTION_KEY).
func NewCipher(envValue string) (*Cipher, error) {
	if len(envValue) < MinKeyLength {
		return nil, fmt.Errorf("LLM_ENCRYPTION_KEY must be at least %d characters (generate one with `openssl rand -hex 32`)", MinKeyLength)
	}
	sum := sha256.Sum256([]byte(envValue))
	return &Cipher{key: sum[:]}, nil
}

// Encrypt seals plaintext and returns base64(nonce || ciphertext).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if c == nil {
		return "", ErrNoCipher
	}
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	if c == nil {
		return "", ErrNoCipher
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	gcm, err := c.gcm()
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, sealed := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (c *Cipher) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
