// Package format encodes/decodes envball bundles to/from bytes. It owns
// the on-disk layout (stub + body + footer) and the CBOR encoding choices
// (deterministic per RFC 8949 §4.2) needed for signature stability.
package format

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"

	"github.com/masaoshima/envball/internal/domain/bundle"
)

// detEncMode is the deterministic CBOR encoder mandated by binary-format
// spec for any body that will be signed. We use it for every encode so
// behavior stays identical between signed and unsigned bundles — the
// signature-bytes-are-stable property then comes "for free" from the
// encoder choice rather than from a separate code path.
var detEncMode = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("envball/format: cannot build deterministic CBOR encoder: " + err.Error())
	}
	return m
}()

// EncodeBody returns a deterministic CBOR encoding of b. Output is
// byte-identical given identical input, which is the property the
// signature scheme depends on.
func EncodeBody(b *bundle.Body) ([]byte, error) {
	out, err := detEncMode.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("envball/format: encode body: %w", err)
	}
	return out, nil
}

// EncodeBodyForSigning produces the byte string that the Ed25519 signer
// signs: the body with every field populated EXCEPT "signature".
// Equivalent to EncodeBody on a Body whose Signature field is nil.
func EncodeBodyForSigning(b *bundle.Body) ([]byte, error) {
	clone := *b
	clone.Signature = nil
	return EncodeBody(&clone)
}

// EncodeAAD returns the CBOR-encoded AAD that binds the encrypted payload
// to its binary_id and scheme, preventing payload swap between bundles.
func EncodeAAD(version, scheme uint64, binaryID []byte) ([]byte, error) {
	aad := struct {
		Version  uint64 `cbor:"version"`
		Scheme   uint64 `cbor:"scheme"`
		BinaryID []byte `cbor:"binary_id"`
	}{Version: version, Scheme: scheme, BinaryID: binaryID}
	out, err := detEncMode.Marshal(aad)
	if err != nil {
		return nil, fmt.Errorf("envball/format: encode aad: %w", err)
	}
	return out, nil
}

// DecodeBody parses a CBOR body back into the domain struct.
func DecodeBody(b []byte) (*bundle.Body, error) {
	var body bundle.Body
	if err := cbor.Unmarshal(b, &body); err != nil {
		return nil, fmt.Errorf("envball/format: decode body: %w", err)
	}
	return &body, nil
}

// EncodeEnvMap serializes an env map (used as the plaintext fed into the
// AEAD). Keys are sorted by the deterministic encoder, which is fine for
// AEAD; the original insertion order is not security-relevant.
func EncodeEnvMap(env map[string]string) ([]byte, error) {
	out, err := detEncMode.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("envball/format: encode env map: %w", err)
	}
	return out, nil
}

// DecodeEnvMap parses an env map from AEAD plaintext.
func DecodeEnvMap(b []byte) (map[string]string, error) {
	var m map[string]string
	if err := cbor.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("envball/format: decode env map: %w", err)
	}
	return m, nil
}

// WriteBundle assembles stub + body + footer into a single executable
// at path with mode 0755. The body offset in the footer is set to the
// stub length so a reader can locate the body without scanning.
func WriteBundle(path string, stub []byte, body []byte) error {
	footer := bundle.Footer{
		BodyOffset:    uint64(len(stub)),
		BodyLength:    uint64(len(body)),
		FormatVersion: bundle.FormatVersion,
	}.Encode()

	var buf bytes.Buffer
	buf.Grow(len(stub) + len(body) + len(footer))
	buf.Write(stub)
	buf.Write(body)
	buf.Write(footer[:])

	tmp, err := os.CreateTemp(dirOf(path), ".envball-out-*")
	if err != nil {
		return fmt.Errorf("envball/format: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("envball/format: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("envball/format: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("envball/format: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("envball/format: rename to %s: %w", path, err)
	}
	return nil
}

// ReadBundleFromFile opens path, locates the footer, and returns the
// parsed Body. NotEnvball is returned (wrapped) when the file lacks the
// footer magic; callers can distinguish "not an envball binary" from
// other I/O errors.
func ReadBundleFromFile(path string) (*bundle.Body, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("envball/format: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("envball/format: stat %s: %w", path, err)
	}
	return ReadBundle(f, stat.Size())
}

// ReadBundle reads the footer-anchored body from any io.ReaderAt whose
// total length the caller knows. Used by the runtime mode entrypoint
// reading its own executable.
func ReadBundle(r io.ReaderAt, size int64) (*bundle.Body, error) {
	if size < bundle.FooterSize {
		return nil, ErrNotEnvball
	}
	tail := make([]byte, bundle.FooterSize)
	if _, err := r.ReadAt(tail, size-bundle.FooterSize); err != nil {
		return nil, fmt.Errorf("envball/format: read footer: %w", err)
	}
	if !bundle.HasFooterMagic(tail) {
		return nil, ErrNotEnvball
	}
	footer, err := bundle.DecodeFooter(tail)
	if err != nil {
		return nil, err
	}
	if int64(footer.BodyOffset)+int64(footer.BodyLength)+bundle.FooterSize > size {
		return nil, bundle.ErrBodyOutOfBounds
	}
	bodyBytes := make([]byte, footer.BodyLength)
	if _, err := r.ReadAt(bodyBytes, int64(footer.BodyOffset)); err != nil {
		return nil, fmt.Errorf("envball/format: read body: %w", err)
	}
	body, err := DecodeBody(bodyBytes)
	if err != nil {
		return nil, err
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	return body, nil
}

// ErrNotEnvball indicates the file lacks the v1 footer magic, i.e. it is
// not an envball binary at all.
var ErrNotEnvball = errors.New("envball: file is not an envball binary")

// Codec satisfies port.BundleCodec by delegating to the package-level
// helpers. Keeps the application layer free of cbor library imports.
type Codec struct{}

// NewCodec returns the production codec adapter.
func NewCodec() Codec { return Codec{} }

func (Codec) EncodeBody(b *bundle.Body) ([]byte, error)           { return EncodeBody(b) }
func (Codec) EncodeBodyForSigning(b *bundle.Body) ([]byte, error) { return EncodeBodyForSigning(b) }
func (Codec) EncodeAAD(version, scheme uint64, binaryID []byte) ([]byte, error) {
	return EncodeAAD(version, scheme, binaryID)
}
func (Codec) EncodeEnvMap(env map[string]string) ([]byte, error)  { return EncodeEnvMap(env) }
func (Codec) DecodeEnvMap(b []byte) (map[string]string, error)    { return DecodeEnvMap(b) }
func (Codec) ReadBundleFromFile(path string) (*bundle.Body, error) {
	return ReadBundleFromFile(path)
}
func (Codec) AssembleBinary(stub, body []byte) ([]byte, error) {
	footer := bundle.Footer{
		BodyOffset:    uint64(len(stub)),
		BodyLength:    uint64(len(body)),
		FormatVersion: bundle.FormatVersion,
	}.Encode()
	out := make([]byte, 0, len(stub)+len(body)+len(footer))
	out = append(out, stub...)
	out = append(out, body...)
	out = append(out, footer[:]...)
	return out, nil
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == os.PathSeparator {
			return p[:i]
		}
	}
	return "."
}
