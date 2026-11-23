// Package envfile parses .env-style files into envset.EnvSet values.
// The parser handles the subset of dotenv syntax that is unambiguous and
// matches POSIX export rules: KEY=VALUE per line, optional `export`
// prefix, `#` comments, blank lines, and single/double-quoted values
// with backslash escapes inside double quotes.
package envfile

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/masaoshima/envball/internal/domain/envset"
)

// Reader implements port.EnvFileReader.
type Reader struct{}

// NewReader returns the production parser.
func NewReader() Reader { return Reader{} }

// Read parses a .env file at path. Errors include the line number to
// help users find the offending entry quickly.
func (Reader) Read(path string) (*envset.EnvSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("envball/envfile: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	set := envset.New()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineno := 0
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		name, value, err := parseLine(stripped)
		if err != nil {
			return nil, fmt.Errorf("envball/envfile: %s:%d: %w", path, lineno, err)
		}
		if err := set.Set(name, value); err != nil {
			return nil, fmt.Errorf("envball/envfile: %s:%d: %w", path, lineno, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("envball/envfile: scan %s: %w", path, err)
	}
	return set, nil
}

var (
	errNoEquals      = errors.New("missing '=' in env line")
	errUnclosedQuote = errors.New("unclosed quote in env value")
	// Message deliberately omits the line content: it may be a secret.
	errTrailingAfterQuote = errors.New("unexpected characters after closing quote (escape inner quotes, or use the other quote style)")
)

func parseLine(line string) (string, string, error) {
	// strip optional `export ` prefix used in shell-sourced .env files
	if rest, ok := strings.CutPrefix(line, "export "); ok {
		line = strings.TrimLeft(rest, " \t")
	}
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", errNoEquals
	}
	name := strings.TrimSpace(line[:eq])
	raw := strings.TrimLeft(line[eq+1:], " \t")

	// strip an unquoted trailing comment ("KEY=val  # note")
	if !startsWithQuote(raw) {
		if hash := strings.Index(raw, " #"); hash >= 0 {
			raw = raw[:hash]
		} else if hash := strings.Index(raw, "\t#"); hash >= 0 {
			raw = raw[:hash]
		}
		raw = strings.TrimRight(raw, " \t")
		return name, raw, nil
	}

	var (
		value    string
		trailing string
		ok       bool
	)
	if raw[0] == '"' {
		value, trailing, ok = scanDoubleQuoted(raw[1:])
	} else {
		value, trailing, ok = scanSingleQuoted(raw[1:])
	}
	if !ok {
		return "", "", errUnclosedQuote
	}
	// Anything after the closing quote other than whitespace or a comment
	// means the quoting is not what the author intended (e.g. KEY='it's').
	// Silently dropping it would truncate a secret, so reject the line.
	trailing = strings.TrimLeft(trailing, " \t")
	if trailing != "" && !strings.HasPrefix(trailing, "#") {
		return "", "", errTrailingAfterQuote
	}
	return name, value, nil
}

// scanSingleQuoted returns the literal text up to the next single quote
// and whatever follows it. Single quotes have no escapes.
func scanSingleQuoted(s string) (value, trailing string, ok bool) {
	end := strings.IndexByte(s, '\'')
	if end < 0 {
		return "", "", false
	}
	return s[:end], s[end+1:], true
}

// scanDoubleQuoted interprets escapes while searching for the closing
// double quote, so an escaped \" is part of the value rather than the
// terminator. Recognised escapes are the ones shells agree on (\n, \r,
// \t, \\, \"); unknown escapes pass through literally so the parser never
// silently drops bytes.
func scanDoubleQuoted(s string) (value, trailing string, ok bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			return b.String(), s[i+1:], true
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			default:
				b.WriteByte('\\')
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

func startsWithQuote(s string) bool {
	if s == "" {
		return false
	}
	return s[0] == '"' || s[0] == '\''
}
