//go:build windows

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// Execer is the windows process executor. Stateless; safe to share.
// Windows has no execve equivalent, so all three port methods funnel
// into a single spawn-and-wait implementation.
type Execer struct{}

// New returns the production executer.
func New() Execer { return Execer{} }

// Exec on Windows is identical to Spawn: spawn child, wait, exit with
// child's code. We never actually replace the process.
func (e Execer) Exec(ctx context.Context, argv []string, env []string) error {
	code, err := e.Spawn(ctx, argv, env)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// Spawn launches argv and waits.
func (Execer) Spawn(ctx context.Context, argv []string, env []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("envball/process: spawn called with empty argv")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("envball/process: run %s: %w", argv[0], err)
	}
	return 0, nil
}

// Supervise on Windows degrades to Spawn since there is no init-style
// supervision on the platform.
func (e Execer) Supervise(ctx context.Context, argv []string, env []string) (int, error) {
	return e.Spawn(ctx, argv, env)
}

// IsPID1 always returns false on Windows; the init-mode concept does
// not apply on this platform.
func IsPID1() bool { return false }
