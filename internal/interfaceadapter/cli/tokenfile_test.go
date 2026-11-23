package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/masaoshima/envball/internal/domain/bundle"
)

func TestWriteTokenFileCreatesMode0600WithHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.ball.token")
	if err := writeTokenFile(path, "tok"); err != nil {
		t.Fatalf("writeTokenFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := bundle.TokenFileHeader + "tok\n"; string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
	assertMode0600(t, path)
}

func TestWriteTokenFileTightensExistingLooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.ball.token")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // defeat umask
		t.Fatalf("chmod fixture: %v", err)
	}
	if err := writeTokenFile(path, "new"); err != nil {
		t.Fatalf("writeTokenFile: %v", err)
	}
	assertMode0600(t, path)
}

func TestWriteTokenFileReplacesSymlinkInsteadOfFollowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-readable")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	path := filepath.Join(dir, "env.ball.token")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := writeTokenFile(path, "secret"); err != nil {
		t.Fatalf("writeTokenFile: %v", err)
	}

	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Fatalf("symlink target was written through: %q", got)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("token path is still a symlink")
	}
	assertMode0600(t, path)
}

func TestWriteTokenFileLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	if err := writeTokenFile(filepath.Join(dir, "env.ball.token"), "tok"); err != nil {
		t.Fatalf("writeTokenFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // POSIX permission bits are not meaningful on Windows
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}
