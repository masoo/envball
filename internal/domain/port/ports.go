// Package port declares the interfaces that the domain and application
// layers need the outside world to satisfy. Every adapter under
// internal/infrastructure implements one of these.
//
// Splitting the ports into one file keeps the interfaces small enough to
// see at a glance, which is the point of hexagonal architecture: a
// reader should not have to chase across packages to know what the
// domain demands.
package port

import (
	"context"
	"io"
	"time"

	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/envset"
)

// BundleCodec handles the (de)serialization of bundles. Concretely it
// owns deterministic CBOR encoding and the stub+body+footer assembly,
// but the application layer treats those as opaque "encode this body to
// bytes". Keeps the application free of cbor/format library deps.
type BundleCodec interface {
	EncodeBody(b *bundle.Body) ([]byte, error)
	EncodeBodyForSigning(b *bundle.Body) ([]byte, error)
	EncodeAAD(version, scheme uint64, binaryID []byte) ([]byte, error)
	EncodeEnvMap(env map[string]string) ([]byte, error)
	DecodeEnvMap(b []byte) (map[string]string, error)
	AssembleBinary(stub, body []byte) ([]byte, error)
	// ReadBundleFromFile loads and validates a bundle from disk.
	// Returns a sentinel-wrapped "not an envball binary" error when the
	// file lacks the v1 footer, distinguishable from other I/O errors.
	ReadBundleFromFile(path string) (*bundle.Body, error)
}

// Cipher performs symmetric AEAD encryption / decryption of the env
// payload. The concrete impl is XChaCha20-Poly1305 with HKDF-SHA256 key
// derivation; tests use a deterministic in-memory fake.
type Cipher interface {
	// DeriveKey produces the 32-byte AEAD key from token random bytes and
	// the per-binary salt (binary_id).
	DeriveKey(tokenRandom, salt []byte) ([]byte, error)
	// Encrypt returns ciphertext-with-tag.
	Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error)
	// Decrypt verifies the tag and returns plaintext. A tag-mismatch
	// surfaces as an error that callers translate to "wrong token or
	// tampered bundle" without leaking which.
	Decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error)
	// NonceSize is the AEAD's nonce size (24 for XChaCha20-Poly1305).
	NonceSize() int
}

// Signer produces and verifies Ed25519 signatures over a deterministic
// CBOR encoding of the body. Optional; v0.1 may build without signing.
type Signer interface {
	Sign(privateKey, message []byte) ([]byte, error)
	Verify(publicKey, message, signature []byte) error
}

// RandomSource is crypto/rand wrapped behind a port so deterministic
// test seeds can be injected. Use only for security-relevant randomness.
type RandomSource interface {
	io.Reader
}

// Clock returns the current wall-clock time. Used to stamp built_at and
// to time-stamp access log entries.
type Clock interface {
	Now() time.Time
}

// EnvFileReader parses a .env-style file into an EnvSet. A separate port
// (rather than passing a parsed map) keeps file-format quirks out of
// the application layer.
type EnvFileReader interface {
	Read(path string) (*envset.EnvSet, error)
}

// ProcessExecer transfers control to the child command with the supplied
// env. Behavior varies by platform; see infrastructure/process for the
// build-tagged implementations.
type ProcessExecer interface {
	// Exec replaces the current process (Linux/macOS, non-PID-1).
	Exec(ctx context.Context, argv []string, env []string) error
	// Supervise spawns the child, forwards POSIX signals, reaps zombies,
	// and returns the child's exit code. Used at PID 1.
	Supervise(ctx context.Context, argv []string, env []string) (exitCode int, err error)
	// Spawn launches the child and waits. Used on Windows.
	Spawn(ctx context.Context, argv []string, env []string) (exitCode int, err error)
}

// AccessLogger records every decrypt+exec for after-the-fact incident
// detection. Never logs values or variable names — only binary id, time,
// cwd, child argv, parent pid.
type AccessLogger interface {
	LogRun(entry AccessEntry) error
}

// AccessEntry is the structured form of one access-log line.
type AccessEntry struct {
	Timestamp    time.Time
	BinaryID     string
	Cwd          string
	ChildArgv    []string
	ParentPID    int
	Mode         string
}

// IgnoreWriter scaffolds the AI/VCS ignore files that envball init
// generates: .gitignore, .aiignore, .cursorignore, .continueignore.
type IgnoreWriter interface {
	EnsureEntries(projectDir string, entries []string) (changed []string, err error)
}

// KeychainStore stores tokens in OS-level credential stores. Reserved
// for v0.2; v0.1 ships only the sibling-file backend.
type KeychainStore interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}
