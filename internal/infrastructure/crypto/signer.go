package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Ed25519Signer implements port.Signer using stdlib crypto/ed25519.
type Ed25519Signer struct{}

// NewSigner returns the v1 Ed25519 signer impl.
func NewSigner() Ed25519Signer { return Ed25519Signer{} }

// Sign produces a 64-byte detached signature over message.
func (Ed25519Signer) Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("envball/crypto: ed25519 private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
}

// Verify reports nil iff the signature is valid for the given public key
// and message; returns a non-nil error otherwise (never panics on bad
// inputs, unlike the stdlib helper).
func (Ed25519Signer) Verify(publicKey, message, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("envball/crypto: ed25519 public key length %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("envball/crypto: ed25519 signature length %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// ErrSignatureInvalid is the sentinel returned by Verify on any
// verification failure. Higher layers should not attempt to distinguish
// "wrong key" from "tampered message"; both indicate a bad bundle.
var ErrSignatureInvalid = errors.New("envball: bundle signature is invalid")
