// Package build orchestrates the BuildBundle use case: read env files,
// encrypt them under a freshly-generated token, and write a
// self-extracting executable to disk.
package build

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/oklog/ulid/v2"

	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/envset"
	"github.com/masaoshima/envball/internal/domain/port"
	"github.com/masaoshima/envball/internal/domain/token"
)

// Input describes one BuildBundle invocation.
type Input struct {
	// EnvFiles is the ordered list of .env paths to parse. Later files
	// override earlier ones, matching the layered-merge domain rule.
	EnvFiles []string
	// StubBytes is the OS executable to use as the outer container. For
	// v0.1 this is the running envball binary with any payload stripped.
	StubBytes []byte
	// Target labels the stub's OS/arch in unencrypted metadata. Does not
	// affect encryption; purely informational.
	Target bundle.Target
	// SigningKey, if non-nil, must be a full Ed25519 private key (64
	// bytes). When set, the body is signed and signer_pubkey embedded.
	SigningKey []byte
	// PresetToken lets a caller supply an already-generated token (e.g.,
	// rotated builds reusing a token). When nil, a fresh one is
	// generated.
	PresetToken *token.Token
}

// Output is what BuildBundle returns to its caller (typically the CLI).
type Output struct {
	BinaryBytes []byte
	Token       token.Token
	Body        *bundle.Body
}

// Service is the application service wiring domain logic to the ports.
type Service struct {
	cipher   port.Cipher
	signer   port.Signer
	random   port.RandomSource
	clock    port.Clock
	envFiles port.EnvFileReader
	codec    port.BundleCodec
}

// NewService constructs the build service from its injected ports.
func NewService(c port.Cipher, s port.Signer, r port.RandomSource, ck port.Clock, ef port.EnvFileReader, cd port.BundleCodec) *Service {
	return &Service{cipher: c, signer: s, random: r, clock: ck, envFiles: ef, codec: cd}
}

// Build parses env files, encrypts, and assembles the bundle bytes.
// The caller is responsible for writing BinaryBytes to disk and persisting
// Token (via sibling file or keychain). This separation keeps the use
// case free of file-path policy.
func (svc *Service) Build(in Input) (*Output, error) {
	if len(in.StubBytes) == 0 {
		return nil, errors.New("envball/build: stub bytes are empty")
	}
	if in.Target.OS == "" {
		in.Target.OS = runtime.GOOS
	}
	if in.Target.Arch == "" {
		in.Target.Arch = runtime.GOARCH
	}

	set, err := svc.loadEnvFiles(in.EnvFiles)
	if err != nil {
		return nil, err
	}
	if set.Len() == 0 {
		return nil, errors.New("envball/build: no env vars found in input files")
	}

	tok, err := svc.resolveToken(in.PresetToken)
	if err != nil {
		return nil, err
	}

	binaryID, err := newBinaryID(svc.random, svc.clock)
	if err != nil {
		return nil, err
	}

	key, err := svc.cipher.DeriveKey(tok.Random(), binaryID)
	if err != nil {
		return nil, fmt.Errorf("envball/build: derive key: %w", err)
	}

	nonce := make([]byte, svc.cipher.NonceSize())
	if _, err := io.ReadFull(svc.random, nonce); err != nil {
		return nil, fmt.Errorf("envball/build: read nonce: %w", err)
	}

	aad, err := svc.codec.EncodeAAD(1, bundle.SchemeXChaCha20Poly1305HKDF, binaryID)
	if err != nil {
		return nil, err
	}

	plaintext, err := svc.codec.EncodeEnvMap(set.AsMap())
	if err != nil {
		return nil, err
	}

	ciphertext, err := svc.cipher.Encrypt(key, nonce, aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("envball/build: encrypt: %w", err)
	}

	body := &bundle.Body{
		Version:      1,
		Scheme:       bundle.SchemeXChaCha20Poly1305HKDF,
		BinaryID:     binaryID,
		BuiltAt:      svc.clock.Now().Format("2006-01-02T15:04:05Z07:00"),
		Target:       in.Target,
		Banner:       bundle.StandardBanner,
		AIBanner:     bundle.StandardAIBanner,
		EncryptedEnv: ciphertext,
		Nonce:        nonce,
	}

	if len(in.SigningKey) > 0 {
		if len(in.SigningKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("envball/build: signing key length %d, want %d", len(in.SigningKey), ed25519.PrivateKeySize)
		}
		body.SignerPubKey = ed25519.PrivateKey(in.SigningKey).Public().(ed25519.PublicKey)
		sigInput, err := svc.codec.EncodeBodyForSigning(body)
		if err != nil {
			return nil, err
		}
		sig, err := svc.signer.Sign(in.SigningKey, sigInput)
		if err != nil {
			return nil, fmt.Errorf("envball/build: sign: %w", err)
		}
		body.Signature = sig
	}

	bodyBytes, err := svc.codec.EncodeBody(body)
	if err != nil {
		return nil, err
	}

	out, err := svc.codec.AssembleBinary(in.StubBytes, bodyBytes)
	if err != nil {
		return nil, err
	}
	return &Output{BinaryBytes: out, Token: tok, Body: body}, nil
}

func (svc *Service) loadEnvFiles(paths []string) (*envset.EnvSet, error) {
	merged := envset.New()
	for _, p := range paths {
		set, err := svc.envFiles.Read(p)
		if err != nil {
			return nil, err
		}
		if err := merged.Merge(set); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

func (svc *Service) resolveToken(preset *token.Token) (token.Token, error) {
	if preset != nil {
		return *preset, nil
	}
	raw := make([]byte, token.RandomLen)
	if _, err := io.ReadFull(svc.random, raw); err != nil {
		return token.Token{}, fmt.Errorf("envball/build: read token randomness: %w", err)
	}
	return token.New(raw)
}

// newBinaryID returns a 16-byte ULID derived from clock + random source.
func newBinaryID(r port.RandomSource, c port.Clock) ([]byte, error) {
	id, err := ulid.New(ulid.Timestamp(c.Now()), r)
	if err != nil {
		return nil, fmt.Errorf("envball/build: ulid: %w", err)
	}
	out := make([]byte, 16)
	copy(out, id[:])
	return out, nil
}
