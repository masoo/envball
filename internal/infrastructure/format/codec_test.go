package format

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/masaoshima/envball/internal/domain/bundle"
)

func validBody() *bundle.Body {
	return &bundle.Body{
		Version:      1,
		Scheme:       bundle.SchemeXChaCha20Poly1305HKDF,
		BinaryID:     bytes.Repeat([]byte{0x01}, 16),
		BuiltAt:      "2026-05-16T00:00:00Z",
		Target:       bundle.Target{OS: "linux", Arch: "amd64"},
		Banner:       bundle.StandardBanner,
		AIBanner:     bundle.StandardAIBanner,
		EncryptedEnv: []byte{0x10, 0x20, 0x30},
		Nonce:        bytes.Repeat([]byte{0x02}, 24),
	}
}

func TestEncodeBodyDeterministic(t *testing.T) {
	b := validBody()
	a1, err := EncodeBody(b)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	a2, err := EncodeBody(b)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	if !bytes.Equal(a1, a2) {
		t.Fatalf("EncodeBody is not deterministic: signatures will not be stable")
	}
}

func TestEncodeDecodeBodyRoundTrip(t *testing.T) {
	b := validBody()
	enc, err := EncodeBody(b)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	got, err := DecodeBody(enc)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if !reflect.DeepEqual(got, b) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, b)
	}
}

func TestEncodeBodyForSigningOmitsSignature(t *testing.T) {
	b := validBody()
	b.Signature = []byte{0xFF}
	b.SignerPubKey = bytes.Repeat([]byte{0xEE}, 32)

	signing, err := EncodeBodyForSigning(b)
	if err != nil {
		t.Fatalf("EncodeBodyForSigning: %v", err)
	}
	dec, err := DecodeBody(signing)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if len(dec.Signature) != 0 {
		t.Fatalf("EncodeBodyForSigning kept signature: %x", dec.Signature)
	}
	if !bytes.Equal(dec.SignerPubKey, b.SignerPubKey) {
		t.Fatalf("EncodeBodyForSigning dropped the pubkey too — should keep")
	}
	// Original body should still have its signature.
	if !bytes.Equal(b.Signature, []byte{0xFF}) {
		t.Fatalf("EncodeBodyForSigning mutated caller's body.Signature")
	}
}

func TestEncodeAADBindsBinaryID(t *testing.T) {
	id1 := bytes.Repeat([]byte{0xAA}, 16)
	id2 := bytes.Repeat([]byte{0xBB}, 16)
	a, _ := EncodeAAD(1, 1, id1)
	b, _ := EncodeAAD(1, 1, id2)
	if bytes.Equal(a, b) {
		t.Fatalf("AAD did not change when binary_id changed")
	}
}

func TestEncodeAADDeterministic(t *testing.T) {
	id := bytes.Repeat([]byte{0xAA}, 16)
	a, _ := EncodeAAD(1, 1, id)
	b, _ := EncodeAAD(1, 1, id)
	if !bytes.Equal(a, b) {
		t.Fatalf("AAD encoding must be deterministic")
	}
}

func TestEncodeDecodeEnvMapRoundTrip(t *testing.T) {
	in := map[string]string{
		"DATABASE_URL": "postgres://example",
		"API_KEY":      "secret",
		"EMPTY":        "",
	}
	enc, err := EncodeEnvMap(in)
	if err != nil {
		t.Fatalf("EncodeEnvMap: %v", err)
	}
	out, err := DecodeEnvMap(enc)
	if err != nil {
		t.Fatalf("DecodeEnvMap: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("env map round-trip mismatch:\n got=%v\nwant=%v", out, in)
	}
}

func TestEncodeEnvMapDeterministic(t *testing.T) {
	in := map[string]string{"A": "1", "B": "2", "C": "3"}
	a, _ := EncodeEnvMap(in)
	b, _ := EncodeEnvMap(in)
	if !bytes.Equal(a, b) {
		t.Fatalf("EncodeEnvMap is not deterministic — AEAD plaintext would be unstable")
	}
}

func TestReadBundleRejectsNonEnvballFile(t *testing.T) {
	r := bytes.NewReader([]byte("just some bytes, no footer here"))
	_, err := ReadBundle(r, int64(r.Len()))
	if !errors.Is(err, ErrNotEnvball) {
		t.Fatalf("ReadBundle on non-envball file should return ErrNotEnvball, got %v", err)
	}
}

func TestReadBundleRejectsTooShortFile(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x02, 0x03})
	_, err := ReadBundle(r, int64(r.Len()))
	if !errors.Is(err, ErrNotEnvball) {
		t.Fatalf("ReadBundle on too-short file should return ErrNotEnvball, got %v", err)
	}
}

func TestWriteAndReadBundleRoundTrip(t *testing.T) {
	body := validBody()
	enc, err := EncodeBody(body)
	if err != nil {
		t.Fatalf("EncodeBody: %v", err)
	}
	stub := []byte("STUB\x00\x00\x00\x00")
	path := filepath.Join(t.TempDir(), "out.bin")
	if err := WriteBundle(path, stub, enc); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("output mode %o, want 0755", info.Mode().Perm())
	}
	got, err := ReadBundleFromFile(path)
	if err != nil {
		t.Fatalf("ReadBundleFromFile: %v", err)
	}
	if !reflect.DeepEqual(got, body) {
		t.Fatalf("written/read bundle mismatch")
	}
}

func TestReadBundleRejectsOutOfBoundsFooter(t *testing.T) {
	// Build a footer that claims a body offset+length larger than the file.
	footer := bundle.Footer{
		BodyOffset:    1 << 30,
		BodyLength:    1 << 30,
		FormatVersion: bundle.FormatVersion,
	}.Encode()
	r := bytes.NewReader(footer[:])
	_, err := ReadBundle(r, int64(r.Len()))
	if !errors.Is(err, bundle.ErrBodyOutOfBounds) {
		t.Fatalf("out-of-bounds footer should return ErrBodyOutOfBounds, got %v", err)
	}
}

func TestCodecAdapterDelegates(t *testing.T) {
	c := NewCodec()
	body := validBody()
	if _, err := c.EncodeBody(body); err != nil {
		t.Errorf("Codec.EncodeBody: %v", err)
	}
	if _, err := c.EncodeBodyForSigning(body); err != nil {
		t.Errorf("Codec.EncodeBodyForSigning: %v", err)
	}
	if _, err := c.EncodeAAD(1, 1, body.BinaryID); err != nil {
		t.Errorf("Codec.EncodeAAD: %v", err)
	}
	stub := []byte("stub")
	enc, _ := c.EncodeBody(body)
	bin, err := c.AssembleBinary(stub, enc)
	if err != nil {
		t.Fatalf("Codec.AssembleBinary: %v", err)
	}
	if !bytes.HasPrefix(bin, stub) {
		t.Fatalf("AssembleBinary output does not start with stub")
	}
	if len(bin) != len(stub)+len(enc)+bundle.FooterSize {
		t.Fatalf("AssembleBinary length = %d, want %d", len(bin), len(stub)+len(enc)+bundle.FooterSize)
	}
}
