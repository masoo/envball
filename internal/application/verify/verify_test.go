package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/masaoshima/envball/internal/application/build"
	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/infrastructure/clock"
	"github.com/masaoshima/envball/internal/infrastructure/crypto"
	"github.com/masaoshima/envball/internal/infrastructure/envfile"
	"github.com/masaoshima/envball/internal/infrastructure/format"
)

func newBuildService() *build.Service {
	return build.NewService(
		crypto.NewCipher(),
		crypto.NewSigner(),
		crypto.NewRandom(),
		clock.New(),
		envfile.NewReader(),
		format.NewCodec(),
	)
}

func writeEnv(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	return p
}

func writeBundle(t *testing.T, signingKey []byte) string {
	t.Helper()
	out, err := newBuildService().Build(build.Input{
		EnvFiles:   []string{writeEnv(t)},
		StubBytes:  []byte("stub-bytes"),
		SigningKey: signingKey,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	path := filepath.Join(t.TempDir(), "env.ball")
	if err := os.WriteFile(path, out.BinaryBytes, 0o755); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestVerifyReadsUnsignedBundleMetadata(t *testing.T) {
	path := writeBundle(t, nil)
	svc := NewService(format.NewCodec(), crypto.NewSigner())
	out, err := svc.Verify(Input{Path: path})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.SignaturePresent {
		t.Errorf("unsigned bundle reported as signed")
	}
	if out.SignatureValid {
		t.Errorf("unsigned bundle reported as valid")
	}
	if out.Body == nil || out.Body.Version != 1 {
		t.Errorf("Body decoded incorrectly: %+v", out.Body)
	}
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := writeBundle(t, priv)
	svc := NewService(format.NewCodec(), crypto.NewSigner())
	out, err := svc.Verify(Input{Path: path})
	if err != nil {
		t.Fatalf("Verify (valid sig): %v", err)
	}
	if !out.SignaturePresent {
		t.Errorf("signed bundle reported as unsigned")
	}
	if !out.SignatureValid {
		t.Errorf("valid signature reported as invalid")
	}
}

func TestVerifyDetectsTamperedSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	out, err := newBuildService().Build(build.Input{
		EnvFiles:   []string{writeEnv(t)},
		StubBytes:  []byte("stub-bytes"),
		SigningKey: priv,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Tamper: flip one byte in the signature.
	out.Body.Signature[0] ^= 0xFF
	body2, err := format.EncodeBody(out.Body)
	if err != nil {
		t.Fatalf("re-encode tampered body: %v", err)
	}
	bin, err := format.NewCodec().AssembleBinary([]byte("stub-bytes"), body2)
	if err != nil {
		t.Fatalf("re-assemble: %v", err)
	}
	path := filepath.Join(t.TempDir(), "env.ball")
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}

	res, err := NewService(format.NewCodec(), crypto.NewSigner()).Verify(Input{Path: path})
	if err == nil {
		t.Fatalf("Verify should fail for tampered signature")
	}
	if !errors.Is(err, crypto.ErrSignatureInvalid) {
		t.Errorf("error should be ErrSignatureInvalid, got %v", err)
	}
	// Output should still report that a signature was present, just invalid.
	if res == nil || !res.SignaturePresent || res.SignatureValid {
		t.Errorf("Output state on bad sig: %+v", res)
	}
}

func TestVerifyRejectsNonEnvballFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(path, []byte("not an envball binary"), 0o644); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	_, err := NewService(format.NewCodec(), crypto.NewSigner()).Verify(Input{Path: path})
	if err == nil {
		t.Fatalf("Verify should reject non-envball file")
	}
	if !errors.Is(err, format.ErrNotEnvball) {
		t.Errorf("expected ErrNotEnvball, got %v", err)
	}
}

func TestVerifyRejectsBundleWithBadVersion(t *testing.T) {
	// Hand-craft a body that fails Validate.
	body := &bundle.Body{
		Version:      99,
		Scheme:       bundle.SchemeXChaCha20Poly1305HKDF,
		BinaryID:     make([]byte, 16),
		Nonce:        make([]byte, 24),
		EncryptedEnv: []byte{0x01},
		Banner:       bundle.StandardBanner,
		AIBanner:     bundle.StandardAIBanner,
	}
	enc, err := format.EncodeBody(body)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	bin, err := format.NewCodec().AssembleBinary([]byte("stub"), enc)
	if err != nil {
		t.Fatalf("AssembleBinary: %v", err)
	}
	path := filepath.Join(t.TempDir(), "env.ball")
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = NewService(format.NewCodec(), crypto.NewSigner()).Verify(Input{Path: path})
	if !errors.Is(err, bundle.ErrBodyVersion) {
		t.Errorf("expected ErrBodyVersion, got %v", err)
	}
}
