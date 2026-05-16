package bundle

import (
	"bytes"
	"testing"
)

func TestFooterEncodeDecodeRoundTrip(t *testing.T) {
	f := Footer{BodyOffset: 5_242_880, BodyLength: 4096, FormatVersion: FormatVersion}
	enc := f.Encode()
	if len(enc) != FooterSize {
		t.Fatalf("footer length %d, want %d", len(enc), FooterSize)
	}
	got, err := DecodeFooter(enc[:])
	if err != nil {
		t.Fatalf("DecodeFooter: %v", err)
	}
	if got != f {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, f)
	}
}

func TestDecodeFooterDetectsBadMagic(t *testing.T) {
	var bad [FooterSize]byte
	if _, err := DecodeFooter(bad[:]); err != ErrFooterMagic {
		t.Fatalf("zero bytes: got err=%v want %v", err, ErrFooterMagic)
	}
}

func TestDecodeFooterRejectsBadVersion(t *testing.T) {
	f := Footer{BodyOffset: 0, BodyLength: 0, FormatVersion: 99}
	enc := f.Encode()
	if _, err := DecodeFooter(enc[:]); err != ErrFormatVersion {
		t.Fatalf("got err=%v want %v", err, ErrFormatVersion)
	}
}

func TestStripPayloadRemovesAttachedPayload(t *testing.T) {
	stub := bytes.Repeat([]byte{'A'}, 1024)
	body := []byte("CBOR-BODY-PLACEHOLDER")
	footer := Footer{BodyOffset: uint64(len(stub)), BodyLength: uint64(len(body)), FormatVersion: FormatVersion}.Encode()
	full := append(append(append([]byte{}, stub...), body...), footer[:]...)

	stripped := StripPayload(full)
	if !bytes.Equal(stripped, stub) {
		t.Fatalf("StripPayload returned %d bytes; want exact stub (%d)", len(stripped), len(stub))
	}
}

func TestStripPayloadIsNoopForBareBinary(t *testing.T) {
	bare := bytes.Repeat([]byte{'B'}, 1024)
	got := StripPayload(bare)
	if !bytes.Equal(got, bare) {
		t.Fatal("StripPayload modified a bare binary")
	}
}

func TestHasFooterMagicTrueForEncoded(t *testing.T) {
	f := Footer{BodyOffset: 100, BodyLength: 50, FormatVersion: FormatVersion}.Encode()
	if !HasFooterMagic(f[:]) {
		t.Fatal("HasFooterMagic returned false for an encoded footer")
	}
}
