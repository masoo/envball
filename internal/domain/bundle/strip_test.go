package bundle

import (
	"bytes"
	"math"
	"testing"
)

func TestBodyFitsIn(t *testing.T) {
	cases := []struct {
		name   string
		offset uint64
		length uint64
		size   int64
		want   bool
	}{
		{"exact fit", 10, 5, 10 + 5 + FooterSize, true},
		{"empty body at end", 10, 0, 10 + FooterSize, true},
		{"one byte too long", 10, 6, 10 + 5 + FooterSize, false},
		{"file smaller than footer", 0, 0, FooterSize - 1, false},
		{"length max uint64", 0, math.MaxUint64, 1 << 20, false},
		{"offset max uint64", math.MaxUint64, 0, 1 << 20, false},
		// offset+length wraps to 0 in uint64 / goes negative in int64
		{"sum wraps to zero", math.MaxUint64 - (1 << 30) + 1, 1 << 30, 1 << 20, false},
		{"offset wraps negative", math.MaxUint64 - FooterSize + 1, 0, 1 << 20, false},
	}
	for _, c := range cases {
		f := Footer{BodyOffset: c.offset, BodyLength: c.length, FormatVersion: FormatVersion}
		if got := f.BodyFitsIn(c.size); got != c.want {
			t.Errorf("%s: BodyFitsIn = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStripPayloadIgnoresOverflowingFooter(t *testing.T) {
	stub := []byte("stub-bytes")
	for _, f := range []Footer{
		{BodyOffset: math.MaxUint64 - FooterSize + 1, BodyLength: 0, FormatVersion: FormatVersion},
		{BodyOffset: 0, BodyLength: math.MaxUint64, FormatVersion: FormatVersion},
	} {
		enc := f.Encode()
		exe := append(append([]byte{}, stub...), enc[:]...)
		// Must not panic; an untrustworthy footer leaves the input as-is.
		if got := StripPayload(exe); !bytes.Equal(got, exe) {
			t.Errorf("footer %+v: StripPayload modified input", f)
		}
	}
}

func TestStripPayloadRemovesValidPayload(t *testing.T) {
	stub := []byte("stub-bytes")
	body := []byte("body")
	enc := Footer{BodyOffset: uint64(len(stub)), BodyLength: uint64(len(body)), FormatVersion: FormatVersion}.Encode()
	exe := append(append(append([]byte{}, stub...), body...), enc[:]...)
	if got := StripPayload(exe); !bytes.Equal(got, stub) {
		t.Fatalf("StripPayload = %q, want %q", got, stub)
	}
}
