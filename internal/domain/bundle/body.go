package bundle

import "errors"

// Encryption scheme codes, per docs/binary-format.md §"Encryption Scheme Codes".
const (
	SchemeXChaCha20Poly1305HKDF uint64 = 0x01
)

// Target describes the OS/arch of the stub the body is paired with.
type Target struct {
	OS   string `cbor:"os"`
	Arch string `cbor:"arch"`
}

// Body is the CBOR-encoded metadata region of an envball binary. The
// struct mirrors the BodyV1 schema in docs/binary-format.md verbatim;
// field tags drive deterministic CBOR encoding.
//
// Invariant: Banner and AIBanner are always the StandardBanner and
// StandardAIBanner constants; EncryptedEnv contains BOTH names and values
// of every env var (names never appear in unencrypted metadata).
type Body struct {
	Version      uint64 `cbor:"version"`
	Scheme       uint64 `cbor:"scheme"`
	BinaryID     []byte `cbor:"binary_id"`
	BuiltAt      string `cbor:"built_at"`
	Target       Target `cbor:"target"`
	Banner       string `cbor:"banner"`
	AIBanner     string `cbor:"ai_banner"`
	EncryptedEnv []byte `cbor:"encrypted_env"`
	Nonce        []byte `cbor:"nonce"`
	SignerPubKey []byte `cbor:"signer_pubkey,omitempty"`
	Signature    []byte `cbor:"signature,omitempty"`
}

var (
	ErrBodyVersion       = errors.New("envball: unsupported body version")
	ErrBodyScheme        = errors.New("envball: unsupported encryption scheme")
	ErrBodyBannerInvalid = errors.New("envball: bundle banner does not match spec")
	ErrBodyMissingField  = errors.New("envball: bundle body is missing a required field")
)

// Validate enforces structural invariants on a freshly-decoded body.
// Cryptographic verification (AEAD tag, Ed25519 signature) happens in
// the application layer; this checks shape and constants only.
func (b *Body) Validate() error {
	if b.Version != 1 {
		return ErrBodyVersion
	}
	if b.Scheme != SchemeXChaCha20Poly1305HKDF {
		return ErrBodyScheme
	}
	if len(b.BinaryID) != 16 {
		return ErrBodyMissingField
	}
	if len(b.Nonce) != 24 {
		return ErrBodyMissingField
	}
	if len(b.EncryptedEnv) == 0 {
		return ErrBodyMissingField
	}
	if b.Banner != StandardBanner || b.AIBanner != StandardAIBanner {
		return ErrBodyBannerInvalid
	}
	return nil
}

// IsSigned reports whether the body carries an Ed25519 signature that a
// caller must verify before trusting metadata.
func (b *Body) IsSigned() bool {
	return len(b.Signature) > 0 && len(b.SignerPubKey) > 0
}
