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
	defer f.Close()

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

	quote := raw[0]
	rest := raw[1:]
	end := strings.IndexByte(rest, quote)
	if end < 0 {
		return "", "", errUnclosedQuote
	}
	value := rest[:end]
	if quote == '"' {
		value = unescapeDouble(value)
	}
	return name, value, nil
}

func startsWithQuote(s string) bool {
	if s == "" {
		return false
	}
	return s[0] == '"' || s[0] == '\''
}

// unescapeDouble interprets the standard double-quote escapes shells
// agree on (\n, \r, \t, \\, \"). Unknown escapes pass through literally
// so the parser never silently drops bytes.
func unescapeDouble(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
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
	}
	return b.String()
}
