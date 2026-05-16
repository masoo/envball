package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	c := NewCipher()
	tokRand := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	k1, err := c.DeriveKey(tokRand, salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	k2, err := c.DeriveKey(tokRand, salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("HKDF is not deterministic for identical inputs")
	}
	if len(k1) != 32 {
		t.Fatalf("DeriveKey returned %d bytes, want 32", len(k1))
	}
}

func TestDeriveKeyDistinctOnSaltChange(t *testing.T) {
	c := NewCipher()
	tokRand := bytes.Repeat([]byte{0x01}, 32)
	salt1 := bytes.Repeat([]byte{0x02}, 16)
	salt2 := bytes.Repeat([]byte{0x03}, 16)
	k1, _ := c.DeriveKey(tokRand, salt1)
	k2, _ := c.DeriveKey(tokRand, salt2)
	if bytes.Equal(k1, k2) {
		t.Fatalf("DeriveKey returned identical key for different salts")
	}
}

func TestDeriveKeyRejectsEmptyInputs(t *testing.T) {
	c := NewCipher()
	if _, err := c.DeriveKey(nil, []byte{0x01}); err == nil {
		t.Errorf("DeriveKey(nil token, ...) should error")
	}
	if _, err := c.DeriveKey([]byte{0x01}, nil); err == nil {
		t.Errorf("DeriveKey(..., nil salt) should error")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := NewCipher()
	key := bytes.Repeat([]byte{0xAA}, 32)
	nonce := bytes.Repeat([]byte{0xBB}, c.NonceSize())
	aad := []byte("aad-binding")
	plaintext := []byte("DATABASE_URL=postgres://example")

	ct, err := c.Encrypt(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatalf("ciphertext equals plaintext — encryption did nothing")
	}
	pt, err := c.Decrypt(key, nonce, aad, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch:\n got=%q\nwant=%q", pt, plaintext)
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	c := NewCipher()
	key := bytes.Repeat([]byte{0xAA}, 32)
	nonce := bytes.Repeat([]byte{0xBB}, c.NonceSize())
	aad := []byte("aad")
	pt := []byte("secret")

	ct, _ := c.Encrypt(key, nonce, aad, pt)
	ct[0] ^= 0xFF
	_, err := c.Decrypt(key, nonce, aad, ct)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("tampered ciphertext should fail with ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptRejectsWrongAAD(t *testing.T) {
	c := NewCipher()
	key := bytes.Repeat([]byte{0xAA}, 32)
	nonce := bytes.Repeat([]byte{0xBB}, c.NonceSize())
	ct, _ := c.Encrypt(key, nonce, []byte("aad-A"), []byte("data"))
	_, err := c.Decrypt(key, nonce, []byte("aad-B"), ct)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("AAD mismatch should fail with ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	c := NewCipher()
	nonce := bytes.Repeat([]byte{0xBB}, c.NonceSize())
	ct, _ := c.Encrypt(bytes.Repeat([]byte{0xAA}, 32), nonce, nil, []byte("data"))
	_, err := c.Decrypt(bytes.Repeat([]byte{0xCC}, 32), nonce, nil, ct)
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("wrong key should fail with ErrDecryptFailed, got %v", err)
	}
}

func TestEncryptRejectsBadNonceLength(t *testing.T) {
	c := NewCipher()
	key := bytes.Repeat([]byte{0xAA}, 32)
	_, err := c.Encrypt(key, []byte{0x00}, nil, []byte("data"))
	if err == nil {
		t.Fatalf("Encrypt with short nonce should error")
	}
}

func TestNonceSizeMatchesXChaCha20(t *testing.T) {
	if NewCipher().NonceSize() != 24 {
		t.Fatalf("XChaCha20-Poly1305 nonce size should be 24")
	}
}

func TestSystemRandomFillsBuffer(t *testing.T) {
	r := NewRandom()
	buf := make([]byte, 32)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 32 {
		t.Fatalf("Read returned %d bytes, want 32", n)
	}
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Fatalf("Read left buffer as zeros — random source is broken")
	}
}

func TestSystemRandomDistinctAcrossCalls(t *testing.T) {
	r := NewRandom()
	a := make([]byte, 32)
	b := make([]byte, 32)
	if _, err := r.Read(a); err != nil {
		t.Fatalf("Read a: %v", err)
	}
	if _, err := r.Read(b); err != nil {
		t.Fatalf("Read b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two random reads returned identical bytes — vanishingly unlikely, suggesting broken source")
	}
}

func TestEd25519SignVerifyRoundTrip(t *testing.T) {
	signer := NewSigner()
	pub, priv, err := generateEd25519(t)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("body-bytes-to-sign")
	sig, err := signer.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.Verify(pub, msg, sig); err != nil {
		t.Fatalf("Verify (good): %v", err)
	}
}

func TestEd25519VerifyRejectsTamperedMessage(t *testing.T) {
	signer := NewSigner()
	pub, priv, _ := generateEd25519(t)
	msg := []byte("original")
	sig, _ := signer.Sign(priv, msg)
	tampered := []byte("tampered")
	err := signer.Verify(pub, tampered, sig)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered message should fail with ErrSignatureInvalid, got %v", err)
	}
}

func TestEd25519VerifyRejectsWrongKey(t *testing.T) {
	signer := NewSigner()
	_, priv, _ := generateEd25519(t)
	otherPub, _, _ := generateEd25519(t)
	msg := []byte("msg")
	sig, _ := signer.Sign(priv, msg)
	err := signer.Verify(otherPub, msg, sig)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong key should fail with ErrSignatureInvalid, got %v", err)
	}
}

func TestEd25519SignRejectsBadKeyLength(t *testing.T) {
	signer := NewSigner()
	if _, err := signer.Sign([]byte{0x01}, []byte("msg")); err == nil {
		t.Errorf("Sign with short key should error")
	}
}

func TestEd25519VerifyRejectsBadInputLengths(t *testing.T) {
	signer := NewSigner()
	pub, priv, _ := generateEd25519(t)
	sig, _ := signer.Sign(priv, []byte("m"))

	if err := signer.Verify([]byte{0x01}, []byte("m"), sig); err == nil {
		t.Errorf("Verify with short public key should error")
	}
	if err := signer.Verify(pub, []byte("m"), []byte{0x01}); err == nil {
		t.Errorf("Verify with short signature should error")
	}
}

func generateEd25519(t *testing.T) (pub, priv []byte, err error) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(p), []byte(k), nil
}
