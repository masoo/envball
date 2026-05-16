package crypto

import "crypto/rand"

// SystemRandom is the production random source backed by crypto/rand.
// It satisfies port.RandomSource via embedded io.Reader semantics.
type SystemRandom struct{}

// NewRandom returns the production random source.
func NewRandom() SystemRandom { return SystemRandom{} }

// Read fills p with cryptographically-secure random bytes.
func (SystemRandom) Read(p []byte) (int, error) { return rand.Read(p) }
