// Package execution encodes the rules that decide how envball-run hands
// control to the child process. Each platform has different syscall-level
// capabilities; the choice between them is a pure-domain decision driven
// by PID context, user flags, and the host OS.
package execution

// Mode names the way envball-run hands control to the child.
type Mode int

const (
	// ModeUnknown is the zero value; callers must always resolve before use.
	ModeUnknown Mode = iota
	// ModeExecReplace replaces the envball-run process via execve. Only
	// available on Linux/macOS. Preferred when not PID 1, since the
	// process tree gains nothing from envball-run remaining alive.
	ModeExecReplace
	// ModeSupervisor keeps envball-run alive as PID 1, forwarding POSIX
	// signals and reaping zombies. Activated when PID 1 is detected.
	ModeSupervisor
	// ModeWindowsSpawn spawns the child and waits. Used unconditionally
	// on Windows, where execve has no equivalent.
	ModeWindowsSpawn
)

// String returns a stable lowercase identifier for logging and the access
// log; do not localize.
func (m Mode) String() string {
	switch m {
	case ModeExecReplace:
		return "exec-replace"
	case ModeSupervisor:
		return "supervisor"
	case ModeWindowsSpawn:
		return "windows-spawn"
	default:
		return "unknown"
	}
}

// FlagOverride lets the caller force a non-default mode via CLI flags.
type FlagOverride int

const (
	// OverrideNone means "decide from PID + OS" (the default).
	OverrideNone FlagOverride = iota
	// OverrideSupervise forces ModeSupervisor regardless of PID. Useful
	// for testing supervisor behavior locally.
	OverrideSupervise
	// OverrideNoInit forces ModeExecReplace regardless of PID, even at
	// PID 1. The CLI warns the user when this combination is unsafe.
	OverrideNoInit
)

// Host describes the runtime environment relevant to mode selection. It
// is supplied by the infrastructure layer (which reads os.Getpid and
// runtime.GOOS) so the domain stays pure.
type Host struct {
	OS    string // "linux", "darwin", "windows"
	IsPID1 bool
}

// Resolve picks the execution mode for the given host and override
// combination. Pure function; no I/O.
func Resolve(host Host, override FlagOverride) Mode {
	if host.OS == "windows" {
		return ModeWindowsSpawn
	}
	switch override {
	case OverrideSupervise:
		return ModeSupervisor
	case OverrideNoInit:
		return ModeExecReplace
	default:
		if host.IsPID1 {
			return ModeSupervisor
		}
		return ModeExecReplace
	}
}

// NoInitAtPID1 reports the unsafe combination of --no-init while running
// as PID 1, so the runtime can surface a warning. The domain only
// classifies; the warning text and writer live in the application layer.
func NoInitAtPID1(host Host, override FlagOverride) bool {
	return host.OS != "windows" && host.IsPID1 && override == OverrideNoInit
}
