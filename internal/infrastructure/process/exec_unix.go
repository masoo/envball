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
func (Execer) Supervise(ctx context.Context, argv []string, env []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("envball/process: supervise called with empty argv")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// New process group so signal forwarding can target the whole group;
	// otherwise envball-run and the child share PGID and a signal we
	// forward to the group also re-enters our handlers.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("envball/process: start %s: %w", argv[0], err)
	}

	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, forwardedSignals...)
	defer signal.Stop(sigCh)

	childPID := cmd.Process.Pid
	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGCHLD {
				reapZombies()
				continue
			}
			_ = syscall.Kill(-childPID, sig.(syscall.Signal))
		case err := <-doneCh:
			reapZombies()
			return exitCodeFrom(cmd, err), nil
		case <-ctx.Done():
			_ = syscall.Kill(-childPID, syscall.SIGTERM)
		}
	}
}

// forwardedSignals matches docs/init-mode.md "Signal Forwarding". SIGCHLD
// is included so the supervisor wakes to reap zombies; it is not
// forwarded to the child.
var forwardedSignals = []os.Signal{
	syscall.SIGTERM,
	syscall.SIGINT,
	syscall.SIGHUP,
	syscall.SIGQUIT,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
	syscall.SIGWINCH,
	syscall.SIGCHLD,
}

// reapZombies non-blockingly waits on every reapable child, so that
// grandchildren whose parents have died don't accumulate as defuncts.
// Only meaningful when envball-run is PID 1, but harmless elsewhere.
func reapZombies() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
	}
}

// exitCodeFrom maps cmd.Wait error to a POSIX-style exit code.
//   - normal exit N         → N
//   - killed by signal S    → 128 + S
//   - start-failure / other → 1
func exitCodeFrom(cmd *exec.Cmd, waitErr error) int {
	if waitErr == nil {
		return 0
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return 1
}

// IsPID1 reports whether this process is currently PID 1. Used by the
// application layer to resolve execution.Mode.
func IsPID1() bool { return os.Getpid() == 1 }
