// Package access writes one JSON line to ~/.envball/access.log per
// decrypt-and-exec. Logged fields are intentionally limited to
// non-secret operational metadata: binary id, time, cwd, child argv,
// parent pid, execution mode. Values and env variable names are NEVER
// logged.
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
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

// ErrNoHomeDir is returned by LogRun when no home directory could be
// resolved, so the caller can warn instead of the run going unrecorded
// silently.
var ErrNoHomeDir = errors.New("envball/access: cannot resolve home directory for ~/.envball/access.log")

// New returns a logger that writes to ~/.envball/access.log. If the home
// directory cannot be resolved, LogRun returns ErrNoHomeDir; it never
// silently skips the record.
func New() *FileLogger {
	home := resolveHome()
	if home == "" {
		return &FileLogger{}
	}
	return &FileLogger{path: filepath.Join(home, ".envball", "access.log")}
}

// resolveHome prefers the account database (passwd on Unix, the user
// profile on Windows) over $HOME. $HOME is set by whoever launches us,
// so trusting it first would let `HOME=/tmp/x ./env.ball` or
// `env -u HOME ./env.ball` redirect or suppress the audit trail. $HOME is
// only a fallback for hosts whose UID has no account entry (e.g.
// containers run with an arbitrary --user).
func resolveHome() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

// LogRun appends one JSON line per access. Errors writing the log are
// returned but should never block the underlying exec — call sites warn
// on stderr and continue.
func (l *FileLogger) LogRun(entry port.AccessEntry) error {
	if l.path == "" {
		return ErrNoHomeDir
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
