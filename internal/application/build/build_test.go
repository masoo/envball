package build

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/token"
	"github.com/masaoshima/envball/internal/infrastructure/clock"
	"github.com/masaoshima/envball/internal/infrastructure/crypto"
	"github.com/masaoshima/envball/internal/infrastructure/envfile"
	"github.com/masaoshima/envball/internal/infrastructure/format"
)

func newService() *Service {
	return NewService(
		crypto.NewCipher(),
		crypto.NewSigner(),
		crypto.NewRandom(),
		clock.New(),
		envfile.NewReader(),
		format.NewCodec(),
	)
}

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return p
}

func TestBuildEncryptsEnvAndProducesRunnableBundle(t *testing.T) {
	envPath := writeEnvFile(t, "DATABASE_URL=postgres://example\nAPI_KEY=secret\n")
	svc := newService()

	out, err := svc.Build(Input{
		EnvFiles:  []string{envPath},
		StubBytes: []byte("stub-bytes-here-not-meaningful"),
		Target:    bundle.Target{OS: "linux", Arch: "amd64"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(out.BinaryBytes) == 0 {
		t.Fatalf("BinaryBytes empty")
	}
	if out.Body == nil {
		t.Fatalf("Body nil")
	}
	if out.Body.Banner != bundle.StandardBanner {
		t.Errorf("Body.Banner not standard")
	}
	if out.Body.AIBanner != bundle.StandardAIBanner {
		t.Errorf("Body.AIBanner not standard")
	}
	if out.Body.Target.OS != "linux" || out.Body.Target.Arch != "amd64" {
		t.Errorf("Body.Target = %+v", out.Body.Target)
	}
	if len(out.Body.Nonce) != 24 {
		t.Errorf("Body.Nonce length = %d, want 24", len(out.Body.Nonce))
	}
	if len(out.Body.BinaryID) != 16 {
		t.Errorf("Body.BinaryID length = %d, want 16", len(out.Body.BinaryID))
	}

	// Encrypted env must not contain plaintext values OR names — that's
	// envball's whole point.
	for _, banned := range []string{"DATABASE_URL", "API_KEY", "postgres://example", "secret"} {
		if bytes.Contains(out.Body.EncryptedEnv, []byte(banned)) {
			t.Errorf("ciphertext leaks plaintext %q", banned)
		}
	}

	// Round-trip: decrypt with the same token and recover the env.
	cipher := crypto.NewCipher()
	codec := format.NewCodec()
	key, err := cipher.DeriveKey(out.Token.Random(), out.Body.BinaryID)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	aad, err := codec.EncodeAAD(out.Body.Version, out.Body.Scheme, out.Body.BinaryID)
	if err != nil {
		t.Fatalf("EncodeAAD: %v", err)
	}
	pt, err := cipher.Decrypt(key, out.Body.Nonce, aad, out.Body.EncryptedEnv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	envMap, err := codec.DecodeEnvMap(pt)
	if err != nil {
		t.Fatalf("DecodeEnvMap: %v", err)
	}
	if envMap["DATABASE_URL"] != "postgres://example" {
		t.Errorf("DATABASE_URL = %q", envMap["DATABASE_URL"])
	}
	if envMap["API_KEY"] != "secret" {
		t.Errorf("API_KEY = %q", envMap["API_KEY"])
	}
}

func TestBuildMergesMultipleEnvFilesLayered(t *testing.T) {
	a := writeEnvFile(t, "SHARED=base\nONLY_A=a\n")
	b := writeEnvFile(t, "SHARED=override\nONLY_B=b\n")
	svc := newService()
	out, err := svc.Build(Input{
		EnvFiles:  []string{a, b},
		StubBytes: []byte("stub"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	envMap := decryptBody(t, out)
	if envMap["SHARED"] != "override" {
		t.Errorf("SHARED = %q, later file should win", envMap["SHARED"])
	}
	if envMap["ONLY_A"] != "a" || envMap["ONLY_B"] != "b" {
		t.Errorf("merged env wrong: %v", envMap)
	}
}

func TestBuildSignsBundleWhenSigningKeyProvided(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	svc := newService()
	out, err := svc.Build(Input{
		EnvFiles:   []string{envPath},
		StubBytes:  []byte("stub"),
		SigningKey: priv,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !out.Body.IsSigned() {
		t.Fatalf("Body should be signed")
	}
	signer := crypto.NewSigner()
	codec := format.NewCodec()
	sigInput, _ := codec.EncodeBodyForSigning(out.Body)
	if err := signer.Verify(out.Body.SignerPubKey, sigInput, out.Body.Signature); err != nil {
		t.Fatalf("signature failed to verify: %v", err)
	}
}

func TestBuildRejectsShortSigningKey(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	svc := newService()
	_, err := svc.Build(Input{
		EnvFiles:   []string{envPath},
		StubBytes:  []byte("stub"),
		SigningKey: []byte{0x01, 0x02},
	})
	if err == nil {
		t.Fatalf("Build should reject short signing key")
	}
}

func TestBuildRejectsEmptyStub(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	svc := newService()
	_, err := svc.Build(Input{EnvFiles: []string{envPath}, StubBytes: nil})
	if err == nil {
		t.Fatalf("Build should reject empty stub")
	}
}

func TestBuildRejectsEmptyEnv(t *testing.T) {
	empty := writeEnvFile(t, "# only comments\n\n")
	svc := newService()
	_, err := svc.Build(Input{EnvFiles: []string{empty}, StubBytes: []byte("stub")})
	if err == nil {
		t.Fatalf("Build should reject zero-env input")
	}
}

func TestBuildHonorsPresetToken(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	raw := bytes.Repeat([]byte{0x5A}, token.RandomLen)
	preset, err := token.New(raw)
	if err != nil {
		t.Fatalf("token.New: %v", err)
	}
	svc := newService()
	out, err := svc.Build(Input{
		EnvFiles:    []string{envPath},
		StubBytes:   []byte("stub"),
		PresetToken: &preset,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(out.Token.Random(), raw) {
		t.Errorf("preset token not used; got different random bytes")
	}
}

func TestBuildDefaultsTargetToHostWhenUnspecified(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	svc := newService()
	out, err := svc.Build(Input{EnvFiles: []string{envPath}, StubBytes: []byte("stub")})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if out.Body.Target.OS == "" || out.Body.Target.Arch == "" {
		t.Errorf("Target should default to host, got %+v", out.Body.Target)
	}
}

func TestBuildGeneratesUniqueBinaryIDAndNonce(t *testing.T) {
	envPath := writeEnvFile(t, "FOO=bar\n")
	svc := newService()
	a, _ := svc.Build(Input{EnvFiles: []string{envPath}, StubBytes: []byte("stub")})
	b, _ := svc.Build(Input{EnvFiles: []string{envPath}, StubBytes: []byte("stub")})
	if bytes.Equal(a.Body.BinaryID, b.Body.BinaryID) {
		t.Errorf("binary_id collided across two builds — randomness broken")
	}
	if bytes.Equal(a.Body.Nonce, b.Body.Nonce) {
		t.Errorf("nonce collided across two builds — catastrophic AEAD reuse")
	}
}

func decryptBody(t *testing.T, out *Output) map[string]string {
	t.Helper()
	cipher := crypto.NewCipher()
	codec := format.NewCodec()
	key, err := cipher.DeriveKey(out.Token.Random(), out.Body.BinaryID)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	aad, err := codec.EncodeAAD(out.Body.Version, out.Body.Scheme, out.Body.BinaryID)
	if err != nil {
		t.Fatalf("EncodeAAD: %v", err)
	}
	pt, err := cipher.Decrypt(key, out.Body.Nonce, aad, out.Body.EncryptedEnv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	m, err := codec.DecodeEnvMap(pt)
	if err != nil {
		t.Fatalf("DecodeEnvMap: %v", err)
	}
	return m
}
