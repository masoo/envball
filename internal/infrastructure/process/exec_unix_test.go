//go:build linux || darwin

package process

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNewIsZeroValue(t *testing.T) {
	if New() != (Execer{}) {
		t.Fatalf("New() should return zero-value Execer")
	}
}

func TestIsPID1ReportsFalseInTestProcess(t *testing.T) {
	// We're running inside `go test`; we are not PID 1.
	if IsPID1() {
		t.Fatalf("IsPID1() = true inside go test — impossible unless containerized weirdly")
	}
}

func TestExecRejectsEmptyArgv(t *testing.T) {
	err := New().Exec(context.Background(), nil, nil)
	if err == nil {
		t.Fatalf("Exec(empty argv) should error")
	}
	if !strings.Contains(err.Error(), "empty argv") {
		t.Errorf("error should mention empty argv, got %v", err)
	}
}

func TestExecRejectsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New().Exec(ctx, []string{"/bin/true"}, nil)
	if err == nil {
		t.Fatalf("Exec with cancelled context should error")
	}
}

func TestExecReportsLookupFailureForUnknownCommand(t *testing.T) {
	err := New().Exec(context.Background(), []string{"definitely-not-a-real-command-9f7ebc12"}, nil)
	if err == nil {
		t.Fatalf("Exec on unknown command should error")
	}
	if !strings.Contains(err.Error(), "cannot locate") {
		t.Errorf("error should explain lookup failure, got %v", err)
	}
}

func TestSuperviseRejectsEmptyArgv(t *testing.T) {
	_, err := New().Supervise(context.Background(), nil, nil)
	if err == nil {
		t.Fatalf("Supervise(empty argv) should error")
	}
}

func TestSuperviseReturnsZeroForCleanExit(t *testing.T) {
	code, err := New().Supervise(context.Background(), []string{"/bin/sh", "-c", "exit 0"}, os.Environ())
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestSuperviseReturnsNonZeroExitCode(t *testing.T) {
	code, err := New().Supervise(context.Background(), []string{"/bin/sh", "-c", "exit 42"}, os.Environ())
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if code != 42 {
		t.Errorf("exit code = %d, want 42", code)
	}
}

func TestSuperviseReturnsSignalExitCode(t *testing.T) {
	// kill -TERM $$ inside the shell results in 128 + SIGTERM(15) = 143.
	code, err := New().Supervise(context.Background(), []string{"/bin/sh", "-c", "kill -TERM $$"}, os.Environ())
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("signal exit code = %d, want %d", code, 128+int(syscall.SIGTERM))
	}
}

func TestSuperviseStartFailureReturnsError(t *testing.T) {
	_, err := New().Supervise(context.Background(), []string{"/no/such/binary-9f7ebc12"}, nil)
	if err == nil {
		t.Fatalf("Supervise should error when start fails")
	}
}

func TestSuperviseCancelledContextTerminatesChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	var code int
	var err error
	start := time.Now()
	go func() {
		defer wg.Done()
		code, err = New().Supervise(ctx, []string{"/bin/sh", "-c", "sleep 30"}, os.Environ())
	}()
	// Give the child a moment to start.
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	// Should have been killed by SIGTERM long before the 30 second sleep.
	if elapsed > 5*time.Second {
		t.Errorf("cancellation didn't terminate child in time, elapsed = %s", elapsed)
	}
	if code == 0 {
		t.Errorf("expected non-zero exit code for terminated child, got 0")
	}
}

func TestSpawnDelegatesToSupervise(t *testing.T) {
	code, err := New().Spawn(context.Background(), []string{"/bin/sh", "-c", "exit 7"}, os.Environ())
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if code != 7 {
		t.Errorf("Spawn exit code = %d, want 7", code)
	}
}

func TestSuperviseRunsInNewProcessGroup(t *testing.T) {
	// The supervised child should be in a different PGID than the test
	// process. We verify by having the child print its PGID and PGID(0).
	// /usr/bin/env /bin/sh -c 'ps ...' is non-portable; check via /proc
	// on Linux only.
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("/proc not available — only Linux can run this assertion")
	}
	testerPGID := syscallGetpgid(t, os.Getpid())
	tmp, err := os.CreateTemp(t.TempDir(), "pgid-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	_ = tmp.Close()
	_, err = New().Supervise(
		context.Background(),
		[]string{"/bin/sh", "-c", "awk '{print $5}' /proc/$$/stat > " + tmp.Name()},
		os.Environ(),
	)
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	data, _ := os.ReadFile(tmp.Name())
	got := strings.TrimSpace(string(data))
	if got == "" {
		t.Fatalf("child failed to write its pgid")
	}
	if got == itoa(testerPGID) {
		t.Errorf("child PGID equals tester PGID (%s) — Setpgid was not honored", got)
	}
}

// TestSuperviseExitCodeIsStableUnderRepetition is the regression test
// for the cmd.Wait vs waitpid(-1) race: the reaper used to win sometimes
// and the exit code collapsed to 1. Repeat enough to make that visible.
func TestSuperviseExitCodeIsStableUnderRepetition(t *testing.T) {
	for i := 0; i < 50; i++ {
		code, err := New().Supervise(context.Background(), []string{"/bin/sh", "-c", "exit 42"}, os.Environ())
		if err != nil {
			t.Fatalf("iteration %d: Supervise: %v", i, err)
		}
		if code != 42 {
			t.Fatalf("iteration %d: exit code = %d, want 42", i, code)
		}
	}
}

// A child that leaves a short-lived background grandchild behind must
// still report its own exit code, not the grandchild's.
func TestSuperviseReportsDirectChildNotGrandchild(t *testing.T) {
	code, err := New().Supervise(context.Background(), []string{"/bin/sh", "-c", "(exit 9) & exit 3"}, os.Environ())
	if err != nil {
		t.Fatalf("Supervise: %v", err)
	}
	if code != 3 {
		t.Errorf("exit code = %d, want 3 (direct child)", code)
	}
}

func waitStatusOf(t *testing.T, script string) syscall.WaitStatus {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	_ = cmd.Run()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("no WaitStatus for %q", script)
	}
	return ws
}

func TestExitCodeFromStatusMapsNormalExit(t *testing.T) {
	if got := exitCodeFromStatus(waitStatusOf(t, "exit 13")); got != 13 {
		t.Errorf("exit code = %d, want 13", got)
	}
}

func TestExitCodeFromStatusMapsSignal(t *testing.T) {
	want := 128 + int(syscall.SIGINT)
	if got := exitCodeFromStatus(waitStatusOf(t, "kill -INT $$")); got != want {
		t.Errorf("signal exit code = %d, want %d", got, want)
	}
}

func TestExitCodeFromStatusZero(t *testing.T) {
	if got := exitCodeFromStatus(waitStatusOf(t, "exit 0")); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestReapChildrenIsSafeWhenNoChildren(t *testing.T) {
	if _, done := reapChildren(-12345); done {
		t.Errorf("reapChildren reported done with no children")
	}
}

func syscallGetpgid(t *testing.T, pid int) int {
	t.Helper()
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("Getpgid(%d): %v", pid, err)
	}
	return pgid
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
