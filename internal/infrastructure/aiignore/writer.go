// Package aiignore generates and updates the family of ignore files that
// keep AI assistants and VCS away from envball binaries and tokens:
// .gitignore, .aiignore, .cursorignore, .continueignore. Each file gets
// a sentinel-delimited managed block so re-runs are idempotent and don't
// disturb user-authored entries.
package aiignore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	beginSentinel = "# >>> envball managed entries >>>"
	endSentinel   = "# <<< envball managed entries <<<"
)

// ManagedFiles is the list of ignore files envball maintains in every
// project. All four are emitted regardless of which AI tools the user
// actually has installed, because the cost of an extra file is trivial
// compared to the cost of forgetting a tool that gets adopted later.
var ManagedFiles = []string{
	".gitignore",
	".aiignore",
	".cursorignore",
	".continueignore",
}

// Writer implements port.IgnoreWriter.
type Writer struct{}

// New returns the production writer.
func New() Writer { return Writer{} }

// EnsureEntries adds entries to every ManagedFile under projectDir, inside
// the envball-managed block. The block is inserted if missing and
// replaced atomically if present. Returns the relative paths of files
// that were created or modified.
func (Writer) EnsureEntries(projectDir string, entries []string) ([]string, error) {
	if projectDir == "" {
		projectDir = "."
	}
	// Preserve insertion order from the caller. The managed-block
	// sentinel makes re-runs idempotent without needing canonical
	// ordering, and keeping grouped comments adjacent to their patterns
	// is more readable.
	entriesCopy := make([]string, len(entries))
	copy(entriesCopy, entries)

	var changed []string
	for _, name := range ManagedFiles {
		path := filepath.Join(projectDir, name)
		mod, err := upsertManagedBlock(path, entriesCopy)
		if err != nil {
			return nil, err
		}
		if mod {
			changed = append(changed, name)
		}
	}
	return changed, nil
}

// upsertManagedBlock rewrites path's managed block to contain exactly
// entries. Returns whether the file was created or its content changed.
func upsertManagedBlock(path string, entries []string) (bool, error) {
	existing, err := os.ReadFile(path)
	created := false
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("envball/aiignore: read %s: %w", path, err)
		}
		existing = nil
		created = true
	}

	rendered := renderBlock(entries)
	var out strings.Builder
	if begin, end := blockBounds(existing); begin >= 0 {
		out.Write(existing[:begin])
		out.WriteString(rendered)
		out.Write(existing[end:])
	} else {
		out.Write(existing)
		if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
			out.WriteByte('\n')
		}
		if len(existing) > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(rendered)
	}
	newContent := out.String()
	if !created && newContent == string(existing) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("envball/aiignore: mkdir parent of %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return false, fmt.Errorf("envball/aiignore: write %s: %w", path, err)
	}
	return true, nil
}

func renderBlock(entries []string) string {
	var b strings.Builder
	b.WriteString(beginSentinel + "\n")
	b.WriteString("# These entries are managed by `envball init`. Do not edit between\n")
	b.WriteString("# the sentinels; envball will overwrite changes on next run.\n")
	for _, e := range entries {
		b.WriteString(e + "\n")
	}
	b.WriteString(endSentinel + "\n")
	return b.String()
}

// blockBounds locates the [begin, end) byte range of an existing managed
// block, end-inclusive of the trailing newline after endSentinel.
// Returns -1, -1 when the block is not present.
func blockBounds(content []byte) (int, int) {
	if len(content) == 0 {
		return -1, -1
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	pos := 0
	beginPos := -1
	endPos := -1
	for scanner.Scan() {
		line := scanner.Text()
		lineLen := len(line) + 1 // account for newline stripped by Scanner
		switch {
		case beginPos < 0 && strings.TrimSpace(line) == beginSentinel:
			beginPos = pos
		case beginPos >= 0 && strings.TrimSpace(line) == endSentinel:
			endPos = pos + lineLen
			return beginPos, endPos
		}
		pos += lineLen
	}
	return -1, -1
}
