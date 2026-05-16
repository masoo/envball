package bundle

import (
	"encoding/binary"
	"errors"
)

// FooterSize is the fixed length of the footer in bytes.
const FooterSize = 32

// FormatVersion is the binary format version this implementation produces.
const FormatVersion uint16 = 1

// LeadingMagic ("ENVBALL\0") marks the start of an envball footer.
var LeadingMagic = [8]byte{'E', 'N', 'V', 'B', 'A', 'L', 'L', 0}

// TrailingMagic ("EB") marks the end of an envball footer.
var TrailingMagic = [2]byte{'E', 'B'}

var (
	ErrFooterTooShort   = errors.New("envball: file too short to contain footer")
	ErrFooterMagic      = errors.New("envball: footer magic mismatch")
	ErrFormatVersion    = errors.New("envball: unsupported format version")
	ErrBodyOutOfBounds  = errors.New("envball: body offset/length out of bounds")
)

// Footer is the 32-byte trailer that identifies an envball binary and
// locates its CBOR-encoded body inside the executable.
type Footer struct {
	BodyOffset    uint64
	BodyLength    uint64
	FormatVersion uint16
}

// Encode serializes the footer to its fixed 32-byte little-endian form.
func (f Footer) Encode() [FooterSize]byte {
	var out [FooterSize]byte
	copy(out[0:8], LeadingMagic[:])
	binary.LittleEndian.PutUint64(out[8:16], f.BodyOffset)
	binary.LittleEndian.PutUint64(out[16:24], f.BodyLength)
	binary.LittleEndian.PutUint16(out[24:26], f.FormatVersion)
	// out[26:30] reserved = 0
	copy(out[30:32], TrailingMagic[:])
	return out
}

// DecodeFooter parses the last 32 bytes of an envball binary. The caller
// supplies exactly FooterSize bytes; non-envball inputs surface as
// ErrFooterMagic and should be treated as "not an envball binary" rather
// than a hard error.
func DecodeFooter(b []byte) (Footer, error) {
	if len(b) != FooterSize {
		return Footer{}, ErrFooterTooShort
	}
	if string(b[0:8]) != string(LeadingMagic[:]) || string(b[30:32]) != string(TrailingMagic[:]) {
		return Footer{}, ErrFooterMagic
	}
	f := Footer{
		BodyOffset:    binary.LittleEndian.Uint64(b[8:16]),
		BodyLength:    binary.LittleEndian.Uint64(b[16:24]),
		FormatVersion: binary.LittleEndian.Uint16(b[24:26]),
	}
	if f.FormatVersion != FormatVersion {
		return f, ErrFormatVersion
	}
	return f, nil
}

// HasFooterMagic reports whether the trailing 32 bytes look like an
// envball footer, without validating the format version or fields. Used
// by the multiplex entrypoint to decide CLI vs runtime mode.
func HasFooterMagic(tail []byte) bool {
	if len(tail) != FooterSize {
		return false
	}
	return string(tail[0:8]) == string(LeadingMagic[:]) &&
		string(tail[30:32]) == string(TrailingMagic[:])
}
