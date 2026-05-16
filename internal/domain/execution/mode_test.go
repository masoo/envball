package execution

import "testing"

func TestResolveDefaultsByPID(t *testing.T) {
	if got := Resolve(Host{OS: "linux", IsPID1: true}, OverrideNone); got != ModeSupervisor {
		t.Fatalf("linux PID1: got %s want supervisor", got)
	}
	if got := Resolve(Host{OS: "linux", IsPID1: false}, OverrideNone); got != ModeExecReplace {
		t.Fatalf("linux non-PID1: got %s want exec-replace", got)
	}
}

func TestResolveWindowsAlwaysSpawn(t *testing.T) {
	for _, override := range []FlagOverride{OverrideNone, OverrideSupervise, OverrideNoInit} {
		if got := Resolve(Host{OS: "windows", IsPID1: false}, override); got != ModeWindowsSpawn {
			t.Fatalf("windows override=%d: got %s want windows-spawn", override, got)
		}
	}
}

func TestOverridesTrumpDefaults(t *testing.T) {
	if got := Resolve(Host{OS: "linux", IsPID1: false}, OverrideSupervise); got != ModeSupervisor {
		t.Fatalf("--supervise outside PID1 should force supervisor; got %s", got)
	}
	if got := Resolve(Host{OS: "linux", IsPID1: true}, OverrideNoInit); got != ModeExecReplace {
		t.Fatalf("--no-init at PID1 should force exec-replace; got %s", got)
	}
}

func TestNoInitAtPID1Flag(t *testing.T) {
	if !NoInitAtPID1(Host{OS: "linux", IsPID1: true}, OverrideNoInit) {
		t.Fatal("expected NoInitAtPID1 to be true")
	}
	if NoInitAtPID1(Host{OS: "linux", IsPID1: false}, OverrideNoInit) {
		t.Fatal("non-PID1 should not flag")
	}
}
