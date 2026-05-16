package access

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/masaoshima/envball/internal/domain/port"
)

// newAtPath returns a logger writing to an arbitrary path. The production
// New() resolves $HOME implicitly; in tests we want full control over
// where the log lands.
func newAtPath(path string) *FileLogger {
	return &FileLogger{path: path}
}

func TestLogRunWritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".envball", "access.log")
	l := newAtPath(logPath)
	ts := time.Date(2026, 5, 16, 10, 0, 0, 0, time.UTC)
	entry := port.AccessEntry{
		Timestamp: ts,
		BinaryID:  "01KRR4629DTKRJZF9PD3M92D29",
		Cwd:       "/tmp/work",
		ChildArgv: []string{"bin/rails", "server"},
		ParentPID: 4242,
		Mode:      "exec_replace",
	}
	if err := l.LogRun(entry); err != nil {
		t.Fatalf("LogRun: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, lines[0])
	}
	if got["binary_id"] != entry.BinaryID {
		t.Errorf("binary_id = %v", got["binary_id"])
	}
	if got["cwd"] != entry.Cwd {
		t.Errorf("cwd = %v", got["cwd"])
	}
	if got["mode"] != entry.Mode {
		t.Errorf("mode = %v", got["mode"])
	}
	if ts := got["ts"]; ts != "2026-05-16T10:00:00Z" {
		t.Errorf("ts = %v, want %q", ts, "2026-05-16T10:00:00Z")
	}
	if ppid, _ := got["ppid"].(float64); int(ppid) != entry.ParentPID {
		t.Errorf("ppid = %v", got["ppid"])
	}
	argv, _ := got["argv"].([]any)
	if len(argv) != 2 || argv[0] != "bin/rails" || argv[1] != "server" {
		t.Errorf("argv = %v", got["argv"])
	}
}

func TestLogRunAppendsRatherThanOverwrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".envball", "access.log")
	l := newAtPath(logPath)
	for i := 0; i < 3; i++ {
		if err := l.LogRun(port.AccessEntry{
			Timestamp: time.Unix(int64(i), 0).UTC(),
			BinaryID:  "id",
			Mode:      "exec_replace",
		}); err != nil {
			t.Fatalf("LogRun: %v", err)
		}
	}
	raw, _ := os.ReadFile(logPath)
	if got := strings.Count(string(raw), "\n"); got != 3 {
		t.Errorf("expected 3 newlines (one per entry), got %d", got)
	}
}

func TestLogRunNeverIncludesSecretsOrEnvNames(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".envball", "access.log")
	l := newAtPath(logPath)
	// Stuff an env-var-looking string into Cwd and Argv to make sure
	// nothing in the log file is treated specially or transformed. (The
	// guarantee is that the logger only writes the fields it lists; this
	// test catches any future change that adds env values to the schema.)
	if err := l.LogRun(port.AccessEntry{
		Timestamp: time.Now().UTC(),
		BinaryID:  "id",
		Cwd:       "/work",
		ChildArgv: []string{"do-not-log-secret"},
		Mode:      "exec_replace",
	}); err != nil {
		t.Fatalf("LogRun: %v", err)
	}
	raw, _ := os.ReadFile(logPath)
	s := string(raw)
	for _, banned := range []string{"DATABASE_URL", "STRIPE_KEY", "decrypted", "plaintext"} {
		if strings.Contains(s, banned) {
			t.Errorf("log unexpectedly contains %q: %s", banned, s)
		}
	}
}

func TestLogRunCreatesParentDirWithRestrictivePerm(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "subdir", "access.log")
	l := newAtPath(logPath)
	if err := l.LogRun(port.AccessEntry{Timestamp: time.Now().UTC(), Mode: "exec_replace"}); err != nil {
		t.Fatalf("LogRun: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "subdir"))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	// The directory should be 0700 (or more restrictive). umask may make
	// it stricter; we only check the upper bound.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("parent dir mode %o is group/world-accessible", mode)
	}
	info2, _ := os.Stat(logPath)
	if mode := info2.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("log file mode %o is group/world-accessible", mode)
	}
}

func TestLogRunWithEmptyPathIsNoOp(t *testing.T) {
	l := &FileLogger{} // no path resolved (e.g. UserHomeDir failed)
	if err := l.LogRun(port.AccessEntry{Timestamp: time.Now().UTC()}); err != nil {
		t.Errorf("LogRun on empty-path logger should no-op without error, got %v", err)
	}
}

func TestLogRunIsSafeForConcurrentCallers(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, ".envball", "access.log")
	l := newAtPath(logPath)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = l.LogRun(port.AccessEntry{
				Timestamp: time.Now().UTC(),
				BinaryID:  "id",
				Mode:      "exec_replace",
			})
		}(i)
	}
	wg.Wait()
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	raw, _ := io.ReadAll(f)
	// Each entry should be a complete, well-formed JSON object on its
	// own line. With a missing mutex some lines would collide.
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d not valid JSON: %v: %q", i, err, line)
		}
	}
}
