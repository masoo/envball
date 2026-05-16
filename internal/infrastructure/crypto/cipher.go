// Package crypto implements the cryptographic ports declared in
// internal/domain/port: AEAD encryption (XChaCha20-Poly1305), key
// derivation (HKDF-SHA256), Ed25519 signing, and a crypto/rand random
// source. The domain layer never imports this package directly.
package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HKDFInfo is the application-specific info string mixed into HKDF, per
// docs/binary-format.md. Changing it invalidates every existing bundle,
// so it doubles as a domain separator for future schemes.
const HKDFInfo = "envball-enc-v1"

// XChaCha20Cipher implements port.Cipher with XChaCha20-Poly1305 +
// HKDF-SHA256. Stateless and safe to share.
type XChaCha20Cipher struct{}

// NewCipher returns the v1 cipher impl.
func NewCipher() XChaCha20Cipher { return XChaCha20Cipher{} }

// DeriveKey runs HKDF-SHA256 with binary_id as salt and HKDFInfo as info.
func (XChaCha20Cipher) DeriveKey(tokenRandom, salt []byte) ([]byte, error) {
	if len(tokenRandom) == 0 {
		return nil, errors.New("envball/crypto: token random material is empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("envball/crypto: salt is empty")
	}
	r := hkdf.New(sha256.New, tokenRandom, salt, []byte(HKDFInfo))
	key := make([]byte, 32)
	if _, err := r.Read(key); err != nil {
		return nil, fmt.Errorf("envball/crypto: hkdf read: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext under XChaCha20-Poly1305 with the supplied AAD.
func (XChaCha20Cipher) Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("envball/crypto: init xchacha: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("envball/crypto: nonce length %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt opens an AEAD ciphertext. A tag-mismatch returns a sentinel
// the application layer translates to "wrong token or tampered bundle".
func (XChaCha20Cipher) Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("envball/crypto: init xchacha: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("envball/crypto: nonce length %d, want %d", len(nonce), aead.NonceSize())
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// NonceSize returns 24 (XChaCha20-Poly1305).
func (XChaCha20Cipher) NonceSize() int { return chacha20poly1305.NonceSizeX }

// ErrDecryptFailed deliberately leaks no information about *why* a
// decryption failed; both "wrong token" and "tampered ciphertext" map
// to this single value, which is how AEAD design intends it.
var ErrDecryptFailed = errors.New("envball: bundle decryption failed (wrong token or tampered binary)")
