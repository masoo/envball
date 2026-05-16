package aiignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureEntriesCreatesAllManagedFiles(t *testing.T) {
	dir := t.TempDir()
	changed, err := New().EnsureEntries(dir, []string{"*.token", "*.bin"})
	if err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if len(changed) != len(ManagedFiles) {
		t.Fatalf("expected %d files changed, got %d (%v)", len(ManagedFiles), len(changed), changed)
	}
	for _, name := range ManagedFiles {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: not created: %v", name, err)
			continue
		}
		s := string(content)
		if !strings.Contains(s, beginSentinel) || !strings.Contains(s, endSentinel) {
			t.Errorf("%s: missing sentinels", name)
		}
		if !strings.Contains(s, "*.token") || !strings.Contains(s, "*.bin") {
			t.Errorf("%s: entries missing", name)
		}
	}
}

func TestEnsureEntriesIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := New().EnsureEntries(dir, []string{"*.token"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := readManaged(t, dir)
	changed, err := New().EnsureEntries(dir, []string{"*.token"})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("second call should report no changes, got %v", changed)
	}
	if got := readManaged(t, dir); got != first {
		t.Errorf("idempotent second call should leave content unchanged")
	}
}

func TestEnsureEntriesReplacesPriorManagedBlock(t *testing.T) {
	dir := t.TempDir()
	if _, err := New().EnsureEntries(dir, []string{"old-entry"}); err != nil {
		t.Fatalf("seed call: %v", err)
	}
	if _, err := New().EnsureEntries(dir, []string{"new-entry"}); err != nil {
		t.Fatalf("update call: %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	s := string(content)
	if strings.Contains(s, "old-entry") {
		t.Errorf("old entry should have been replaced, got %q", s)
	}
	if !strings.Contains(s, "new-entry") {
		t.Errorf("new entry missing, got %q", s)
	}
	// And the block should appear exactly once.
	if strings.Count(s, beginSentinel) != 1 {
		t.Errorf("begin sentinel appears %d times, want 1: %q", strings.Count(s, beginSentinel), s)
	}
}

func TestEnsureEntriesPreservesUserContent(t *testing.T) {
	dir := t.TempDir()
	userContent := "# my own rules\nnode_modules/\n*.log\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(userContent), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if _, err := New().EnsureEntries(dir, []string{"*.token"}); err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	s := string(content)
	if !strings.Contains(s, "node_modules/") || !strings.Contains(s, "*.log") {
		t.Errorf("user content should be preserved, got %q", s)
	}
	if !strings.Contains(s, "*.token") {
		t.Errorf("managed block should be appended, got %q", s)
	}
	if !strings.HasPrefix(s, "# my own rules") {
		t.Errorf("user content should remain at the top, got %q", s)
	}
}

func TestEnsureEntriesEmptyProjectDirDefaultsToCwd(t *testing.T) {
	// Run in an isolated cwd so we don't pollute the real project dir.
	dir := t.TempDir()
	saved, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(saved) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if _, err := New().EnsureEntries("", []string{"*.token"}); err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err != nil {
		t.Errorf(".gitignore not created in cwd: %v", err)
	}
}

func TestEnsureEntriesPreservesMultipleEntriesOrder(t *testing.T) {
	dir := t.TempDir()
	entries := []string{"first", "second", "third"}
	if _, err := New().EnsureEntries(dir, entries); err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	s := string(content)
	iFirst := strings.Index(s, "first")
	iSecond := strings.Index(s, "second")
	iThird := strings.Index(s, "third")
	if !(iFirst >= 0 && iFirst < iSecond && iSecond < iThird) {
		t.Errorf("entries not in caller-supplied order:\n%s", s)
	}
}

func readManaged(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range ManagedFiles {
		c, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.WriteString(name)
		b.WriteByte('\n')
		b.Write(c)
		b.WriteByte('\n')
	}
	return b.String()
}
