package token

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Prefix is the literal leading marker on every envball token.
const Prefix = "envb_"

// RandomLen is the size in bytes of the random material a token carries.
const RandomLen = 32

// ChecksumChars is the number of base32 characters of checksum included
// in the rendered token. 20 bits of checksum catches typos cheaply
// without bloating the token.
const ChecksumChars = 4

// ChecksumVersion is the first byte mixed into the checksum hash, allowing
// a future token format change without ambiguous parsing.
const ChecksumVersion byte = 0x01

var (
	ErrFormat    = errors.New("envball: invalid token format")
	ErrChecksum  = errors.New("envball: token checksum mismatch (likely a typo)")
	ErrLength    = errors.New("envball: token random component has wrong length")
)

// Token is a parsed, checksum-verified envball token. The zero value is
// invalid; always construct via New or Parse.
type Token struct {
	random [RandomLen]byte
}

// New wraps freshly-generated random bytes as a Token. The caller is
// responsible for using crypto/rand.
func New(random []byte) (Token, error) {
	if len(random) != RandomLen {
		return Token{}, ErrLength
	}
	var t Token
	copy(t.random[:], random)
	return t, nil
}

// Random returns a copy of the token's random component. Callers feed
// this into HKDF to derive the AEAD key.
func (t Token) Random() []byte {
	out := make([]byte, RandomLen)
	copy(out, t.random[:])
	return out
}

// String renders the token in its canonical "envb_<b64u>_<chk>" form.
func (t Token) String() string {
	body := base64.RawURLEncoding.EncodeToString(t.random[:])
	return Prefix + body + "_" + checksum(t.random[:])
}

// Parse validates and decodes a token string. Leading/trailing whitespace
// and any '#'-prefixed lines (per the on-disk token file format) are
// stripped before parsing, so callers can pass raw file contents.
//
// Token structure: "envb_" + <43-char base64url> + "_" + <4-char base32 checksum>.
// We split on the LAST underscore rather than on every underscore,
// because base64url's alphabet includes '_' itself; a naive Split would
// reject perfectly valid tokens.
func Parse(s string) (Token, error) {
	s = stripTokenFileNoise(s)
	if !strings.HasPrefix(s, Prefix) {
		return Token{}, fmt.Errorf("%w: missing %q prefix", ErrFormat, Prefix)
	}
	rest := strings.TrimPrefix(s, Prefix)
	cut := strings.LastIndexByte(rest, '_')
	if cut < 0 {
		return Token{}, fmt.Errorf("%w: missing checksum separator", ErrFormat)
	}
	randomPart := rest[:cut]
	checksumPart := rest[cut+1:]
	if len(checksumPart) != ChecksumChars {
		return Token{}, fmt.Errorf("%w: checksum length %d, want %d", ErrFormat, len(checksumPart), ChecksumChars)
	}
	raw, err := base64.RawURLEncoding.DecodeString(randomPart)
	if err != nil {
		return Token{}, fmt.Errorf("%w: random part is not valid base64url: %v", ErrFormat, err)
	}
	if len(raw) != RandomLen {
		return Token{}, fmt.Errorf("%w: decoded %d bytes, want %d", ErrLength, len(raw), RandomLen)
	}
	want := checksum(raw)
	if !strings.EqualFold(checksumPart, want) {
		return Token{}, ErrChecksum
	}
	var t Token
	copy(t.random[:], raw)
	return t, nil
}

func checksum(random []byte) string {
	h := sha256.New()
	h.Write([]byte{ChecksumVersion})
	h.Write(random)
	sum := h.Sum(nil)[:4]
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum)
	return strings.ToLower(enc)[:ChecksumChars]
}

// stripTokenFileNoise removes blank lines and '#'-prefixed comment lines
// so that a token file (with its mandatory AI-instruction header) can be
// passed verbatim to Parse.
func stripTokenFileNoise(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		b.WriteString(trimmed)
	}
	return b.String()
}
