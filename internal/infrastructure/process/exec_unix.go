//go:build linux || darwin

// Package process implements port.ProcessExecer with platform-specific
// build tags. The Unix path uses syscall.Exec for true process
// replacement and a minimal supervisor for PID 1 / Docker-style use.
package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Execer is the unix process executor. Stateless; safe to share.
type Execer struct{}

// New returns the production executer.
func New() Execer { return Execer{} }

// Exec replaces the current process with argv via syscall.Exec. On
// success this function never returns; on failure the underlying execve
// error is wrapped and returned.
func (Execer) Exec(ctx context.Context, argv []string, env []string) error {
	if len(argv) == 0 {
		return errors.New("envball/process: exec called with empty argv")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("envball/process: cannot locate %q: %w", argv[0], err)
	}
	if err := syscall.Exec(bin, argv, env); err != nil {
		return fmt.Errorf("envball/process: execve %s: %w", bin, err)
	}
	return nil // unreachable on success
}

// Spawn is a unix alias for Supervise without signal forwarding; v0.1
// only calls Exec or Supervise via the application layer, but the port
// requires Spawn so Windows code can also satisfy it.
func (e Execer) Spawn(ctx context.Context, argv []string, env []string) (int, error) {
	return e.Supervise(ctx, argv, env)
}

// Supervise spawns argv, forwards a fixed set of POSIX signals to the
// child's process group, reaps any zombies on SIGCHLD, and returns
// (exitCode, nil) when the child exits. The set of forwarded signals
// matches docs/init-mode.md; signals like SIGSEGV/SIGBUS/SIGFPE are
// intentionally NOT forwarded.
//
// The reap loop is the ONLY place that waits for children. cmd.Wait is
// deliberately not used: a concurrent cmd.Wait and waitpid(-1) race for
// the direct child, and when waitpid(-1) wins, cmd.Wait gets ECHILD and
// the real exit status is lost (it used to surface as exit code 1).
// Instead the reap loop records the direct child's WaitStatus itself, the
// same way tini does.
func (Execer) Supervise(ctx context.Context, argv []string, env []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("envball/process: supervise called with empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// New process group so signal forwarding can target the whole group;
	// otherwise envball-run and the child share PGID and a signal we
	// forward to the group also re-enters our handlers.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Install handlers BEFORE starting the child, so a signal arriving
	// right after Start is forwarded rather than killing envball and
	// orphaning the child.
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, forwardedSignals...)
	defer signal.Stop(sigCh)
	// SIGCHLD gets its own 1-slot channel: one pending notification is
	// enough because each wake-up drains every reapable child, and it can
	// never be crowded out by a burst of forwarded signals.
	chldCh := make(chan os.Signal, 1)
	signal.Notify(chldCh, syscall.SIGCHLD)
	defer signal.Stop(chldCh)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("envball/process: start %s: %w", argv[0], err)
	}
	// We reap via wait4 ourselves; release os/exec's handle (pidfd).
	defer func() { _ = cmd.Process.Release() }()
	childPID := cmd.Process.Pid

	// The child may already have exited before SIGCHLD was observed.
	if ws, done := reapChildren(childPID); done {
		return exitCodeFromStatus(ws), nil
	}

	ctxDone := ctx.Done()
	var killTimer <-chan time.Time
	for {
		select {
		case sig := <-sigCh:
			_ = syscall.Kill(-childPID, sig.(syscall.Signal))
		case <-chldCh:
			if ws, done := reapChildren(childPID); done {
				return exitCodeFromStatus(ws), nil
			}
		case <-ctxDone:
			// Ask once, then escalate; never spin on a closed Done channel.
			_ = syscall.Kill(-childPID, syscall.SIGTERM)
			ctxDone = nil
			killTimer = time.After(cancelGracePeriod)
		case <-killTimer:
			_ = syscall.Kill(-childPID, syscall.SIGKILL)
			killTimer = nil
		}
	}
}

// cancelGracePeriod is how long Supervise waits after SIGTERM on context
// cancellation before sending SIGKILL to the child's process group.
const cancelGracePeriod = 10 * time.Second

// forwardedSignals matches docs/init-mode.md "Signal Forwarding".
// SIGCHLD is handled separately (see Supervise) and never forwarded.
var forwardedSignals = []os.Signal{
	syscall.SIGTERM,
	syscall.SIGINT,
	syscall.SIGHUP,
	syscall.SIGQUIT,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
	syscall.SIGWINCH,
}

// reapChildren non-blockingly waits on every reapable child, so that
// grandchildren whose parents have died don't accumulate as defuncts.
// If the direct child (childPID) is among them, its status is returned
// with done=true. Reaping of orphans is only meaningful when envball-run
// is PID 1, but harmless elsewhere.
func reapChildren(childPID int) (status syscall.WaitStatus, done bool) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if pid <= 0 || err != nil {
			return status, done
		}
		if pid == childPID {
			status, done = ws, true
		}
	}
}

// exitCodeFromStatus maps a wait status to a POSIX-style exit code.
//   - normal exit N      → N
//   - killed by signal S → 128 + S
func exitCodeFromStatus(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// IsPID1 reports whether this process is currently PID 1. Used by the
// application layer to resolve execution.Mode.
func IsPID1() bool { return os.Getpid() == 1 }
