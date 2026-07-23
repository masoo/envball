// Package access writes one JSON line to ~/.envball/access.log per
// decrypt-and-exec. Logged fields are intentionally limited to
// non-secret operational metadata: binary id, time, cwd, child argv,
// parent pid, execution mode. Values and env variable names are NEVER
// logged.
package access

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/masaoshima/envball/internal/domain/port"
)

// FileLogger writes JSON lines to a per-user access log. Safe for
// concurrent use within the same process; cross-process safety is
// provided by O_APPEND on POSIX.
type FileLogger struct {
	mu   sync.Mutex
	path string
}

// New returns a logger that writes to ~/.envball/access.log. If the
// home directory cannot be resolved, log writes silently no-op so that
// missing-HOME does not break envball-run.
func New() *FileLogger {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return &FileLogger{}
	}
	return &FileLogger{path: filepath.Join(home, ".envball", "access.log")}
}

// LogRun appends one JSON line per access. Errors writing the log are
// returned but should never block the underlying exec — call sites log
// the error and continue.
func (l *FileLogger) LogRun(entry port.AccessEntry) error {
	if l.path == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return fmt.Errorf("envball/access: mkdir log dir: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("envball/access: open log: %w", err)
	}
	defer func() { _ = f.Close() }()
	rec := struct {
		Timestamp string   `json:"ts"`
		BinaryID  string   `json:"binary_id"`
		Cwd       string   `json:"cwd"`
		Argv      []string `json:"argv"`
		ParentPID int      `json:"ppid"`
		Mode      string   `json:"mode"`
	}{
		Timestamp: entry.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		BinaryID:  entry.BinaryID,
		Cwd:       entry.Cwd,
		Argv:      entry.ChildArgv,
		ParentPID: entry.ParentPID,
		Mode:      entry.Mode,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("envball/access: marshal log entry: %w", err)
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("envball/access: write log: %w", err)
	}
	return nil
}
