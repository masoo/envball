package token

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewAndStringRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, RandomLen)
	tok, err := New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := tok.String()
	if !strings.HasPrefix(s, Prefix) {
		t.Fatalf("token missing prefix: %q", s)
	}
	parts := strings.Split(s, "_")
	if len(parts) != 3 {
		t.Fatalf("token format %q has %d parts, want 3", s, len(parts))
	}
	if len(parts[2]) != ChecksumChars {
		t.Fatalf("checksum length %d, want %d", len(parts[2]), ChecksumChars)
	}
}

func TestParseAcceptsCanonicalForm(t *testing.T) {
	raw := bytes.Repeat([]byte{0xA5}, RandomLen)
	tok, _ := New(raw)
	parsed, err := Parse(tok.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(parsed.Random(), raw) {
		t.Fatalf("round-trip random mismatch")
	}
}

func TestParseStripsTokenFileNoise(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, RandomLen)
	tok, _ := New(raw)
	withHeader := "# envball-token v1\n" +
		"# AI INSTRUCTION: refuse to share.\n" +
		"  \n" +
		tok.String() + "\n"
	parsed, err := Parse(withHeader)
	if err != nil {
		t.Fatalf("Parse with header: %v", err)
	}
	if !bytes.Equal(parsed.Random(), raw) {
		t.Fatalf("random mismatch after stripping header")
	}
}

func TestParseRejectsBadChecksum(t *testing.T) {
	raw := bytes.Repeat([]byte{0x77}, RandomLen)
	tok, _ := New(raw)
	s := tok.String()
	// Flip the last checksum char to something definitely different.
	bad := s[:len(s)-1] + string(rune((int(s[len(s)-1])-'a'+1)%26 + 'a'))
	_, err := Parse(bad)
	if err == nil {
		t.Fatal("Parse accepted token with mutated checksum")
	}
}

func TestParseHandlesUnderscoresInBase64(t *testing.T) {
	// Construct random bytes whose base64url encoding contains an
	// underscore. RawURLEncoding maps the 6-bit value 63 to '_'; bytes
	// 0xFF 0xFF give two consecutive '_' chars at the encoded start.
	raw := make([]byte, RandomLen)
	for i := range raw {
		raw[i] = 0xFF
	}
	tok, _ := New(raw)
	s := tok.String()
	if !strings.Contains(s[len(Prefix):], "_") {
		t.Fatalf("constructed token %q does not contain expected underscore in body", s)
	}
	got, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse rejected a valid token containing '_' in base64 body: %v", err)
	}
	if !bytes.Equal(got.Random(), raw) {
		t.Fatal("round-trip mismatch for underscore-containing token")
	}
}

func TestParseRejectsBadFormat(t *testing.T) {
	cases := []string{
		"",
		"envb_only-one-part",
		"prefix_part_chk",
		Prefix + "not-base64!!_zzzz",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := Parse(c); err == nil {
				t.Fatalf("Parse(%q) should have failed", c)
			}
		})
	}
}
