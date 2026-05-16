package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func TestReadParsesBasicKeyValue(t *testing.T) {
	p := writeFile(t, "DATABASE_URL=postgres://example\nAPI_KEY=secret\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("DATABASE_URL"); v != "postgres://example" {
		t.Errorf("DATABASE_URL = %q", v)
	}
	if v, _ := set.Get("API_KEY"); v != "secret" {
		t.Errorf("API_KEY = %q", v)
	}
}

func TestReadIgnoresCommentsAndBlankLines(t *testing.T) {
	p := writeFile(t, `# leading comment

# another comment
   # indented comment
FOO=bar

# trailing comment
`)
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("expected 1 var, got %d (%v)", set.Len(), set.Names())
	}
}

func TestReadHandlesExportPrefix(t *testing.T) {
	p := writeFile(t, "export FOO=bar\nexport   BAZ=qux\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("FOO"); v != "bar" {
		t.Errorf("FOO = %q, want %q", v, "bar")
	}
	if v, _ := set.Get("BAZ"); v != "qux" {
		t.Errorf("BAZ = %q, want %q", v, "qux")
	}
}

func TestReadHandlesDoubleQuotedValues(t *testing.T) {
	// \" inside double quotes is NOT supported by the current parser
	// (the closing quote is located by raw byte search before escape
	// processing). Tests exercise the documented escapes: \n \r \t \\.
	p := writeFile(t, `MSG="hello world"`+"\n"+`ESC="line1\nline2\ttab\\back"`+"\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("MSG"); v != "hello world" {
		t.Errorf("MSG = %q", v)
	}
	if v, _ := set.Get("ESC"); v != "line1\nline2\ttab\\back" {
		t.Errorf("ESC = %q", v)
	}
}

func TestReadDoubleQuoteUnknownEscapePassesThroughLiterally(t *testing.T) {
	// \x is not a recognised escape; the parser keeps the backslash
	// and the next byte intact so no data is silently dropped.
	p := writeFile(t, `M="a\xb"`+"\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("M"); v != `a\xb` {
		t.Errorf("M = %q, want %q", v, `a\xb`)
	}
}

func TestReadHandlesSingleQuotedValuesLiterally(t *testing.T) {
	p := writeFile(t, `RAW='no \n escape here'`+"\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("RAW"); v != `no \n escape here` {
		t.Errorf("RAW = %q (single quotes should not interpret \\n)", v)
	}
}

func TestReadStripsTrailingUnquotedComment(t *testing.T) {
	p := writeFile(t, "PORT=8080  # primary http port\nNAME=foo\t# tab comment\n")
	set, _ := NewReader().Read(p)
	if v, _ := set.Get("PORT"); v != "8080" {
		t.Errorf("PORT = %q (trailing comment should be stripped)", v)
	}
	if v, _ := set.Get("NAME"); v != "foo" {
		t.Errorf("NAME = %q", v)
	}
}

func TestReadDoesNotStripCommentInsideQuotes(t *testing.T) {
	p := writeFile(t, `MSG="value with # not a comment"`+"\n")
	set, _ := NewReader().Read(p)
	if v, _ := set.Get("MSG"); v != "value with # not a comment" {
		t.Errorf("MSG = %q (# inside quotes must be preserved)", v)
	}
}

func TestReadMissingEqualsErrorIncludesLineNumber(t *testing.T) {
	p := writeFile(t, "VALID=ok\nBROKEN line\nALSO_VALID=yes\n")
	_, err := NewReader().Read(p)
	if err == nil {
		t.Fatalf("Read should error on missing '='")
	}
	if !strings.Contains(err.Error(), ":2:") {
		t.Errorf("error should report line 2 prefix, got %q", err.Error())
	}
}

func TestReadUnclosedQuoteIsError(t *testing.T) {
	p := writeFile(t, `MSG="open and never close`+"\n")
	_, err := NewReader().Read(p)
	if err == nil {
		t.Fatalf("Read should error on unclosed quote")
	}
}

func TestReadInvalidVariableNameIsError(t *testing.T) {
	p := writeFile(t, "1BAD=value\n")
	_, err := NewReader().Read(p)
	if err == nil {
		t.Fatalf("Read should reject names starting with a digit")
	}
}

func TestReadLaterEntryOverwritesEarlier(t *testing.T) {
	p := writeFile(t, "FOO=first\nFOO=second\n")
	set, err := NewReader().Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v, _ := set.Get("FOO"); v != "second" {
		t.Errorf("FOO = %q, want %q", v, "second")
	}
	if set.Len() != 1 {
		t.Errorf("expected 1 var after dedup, got %d", set.Len())
	}
}

func TestReadMissingFileError(t *testing.T) {
	_, err := NewReader().Read(filepath.Join(t.TempDir(), "absent.env"))
	if err == nil {
		t.Fatalf("Read on missing file should error")
	}
}
