# envball-run Init Mode

`envball-run` decrypts an envball binary and execs its child process. In
container environments where `envball-run` is PID 1, it additionally
performs init duties (signal forwarding, zombie reaping, exit code
propagation).

This document explains when init mode activates, how it behaves, and how
it interoperates with `tini`, `dumb-init`, `s6-overlay`, and Docker
`--init`.

## When Init Mode Activates

| Condition                          | Behavior                       |
|------------------------------------|--------------------------------|
| Linux/macOS, PID 1, no flag        | **Supervisor mode** (auto)     |
| Linux/macOS, PID != 1, no flag     | **Exec-replace** (auto)        |
| Linux/macOS, `--supervise`         | Supervisor mode (forced)       |
| Linux/macOS, `--no-init`           | Exec-replace (forced)          |
| Linux/macOS, PID 1, `--no-init`    | Exec-replace + warning to stderr |
| Windows, any                       | Spawn-and-wait (always)        |

On Windows there is no POSIX `execve` equivalent, so `envball-run`
always spawns a child and waits. The `--supervise` / `--no-init` flags
are accepted but have no effect on the underlying model.

## Supervisor Mode Behavior (Linux/macOS)

When acting as PID 1, `envball-run` performs the following init duties.

### Signal Forwarding

`envball-run` installs handlers for these POSIX signals and forwards
each received signal to the child process group:

    SIGTERM   SIGINT    SIGHUP    SIGQUIT
    SIGUSR1   SIGUSR2   SIGWINCH

Signals not in this list are not forwarded — most are kernel-only or
unsafe to forward (e.g., SIGSEGV, SIGBUS, SIGFPE).

### Zombie Reaping

On SIGCHLD, `envball-run` loops calling `waitpid(-1, ..., WNOHANG)`
until no zombies remain. This ensures that grandchildren whose parents
have died are reaped, not left as defunct processes that exhaust the
PID table.

### Exit Code Propagation

When the direct child exits, `envball-run` exits with the same code:

- Child exits 0 → `envball-run` exits 0.
- Child exits N → `envball-run` exits N.
- Child killed by signal S → `envball-run` exits `128 + S` (POSIX
  convention).

### What Supervisor Mode Does NOT Do

To keep `envball-run` minimal and predictable, supervisor mode
intentionally OMITS:

- **Subreaper via `prctl(PR_SET_CHILD_SUBREAPER)`**. `tini` supports
  this for advanced process tree reparenting. Chain `tini` if needed.
- **Process group leadership management** beyond the default. `tini`
  has `-g` for this.
- **Verbose logging of signals received**. `tini` has `-v`.
- **Configurable signal subsets** or signal mapping. The set above is
  fixed.

If your workload needs these features, chain `tini` before `envball-run`:

    ENTRYPOINT ["tini", "-g", "--", "envball-run", "--", "bin/rails", "server"]

This is supported and tested.

## Docker Usage Patterns

### Pattern A: Recommended — `envball-run` as Entrypoint

    ENTRYPOINT ["envball-run", "--", "bin/rails", "server"]

`envball-run` is PID 1, detects this, and acts as supervisor. No tini
or dumb-init required. Suitable for most workloads.

### Pattern B: With tini or dumb-init

    ENTRYPOINT ["tini", "--", "envball-run", "--", "bin/rails", "server"]

`tini` is PID 1. `envball-run` is PID 2 and uses `syscall.Exec` to
replace itself with the child (which becomes PID 2). `tini` handles
init duties. Choose this when:

- Your organization already standardizes on `tini` / `dumb-init`.
- You need `tini`'s advanced features (subreaper, process group).
- You prefer the Unix-philosophy separation of concerns.

### Pattern C: With Docker `--init`

    docker run --init my-image

Same Dockerfile as Pattern A. Docker injects `tini` at PID 1
transparently; `envball-run` runs as PID 2 and uses `syscall.Exec`.
Effectively identical to Pattern B but configured at runtime.

In docker-compose:

    services:
      api:
        image: my-image
        init: true

### Pattern D: Kubernetes

In a Kubernetes pod spec, `envball-run` is the entrypoint of the
container. It is typically PID 1 inside the container (unless you've
configured `shareProcessNamespace`, in which case the rules of the
shared namespace apply).

    spec:
      containers:
      - name: api
        image: my-image
        command: ["envball-run", "--", "bin/rails", "server"]

Pod-level termination grace period (`terminationGracePeriodSeconds`)
gives the child time to handle the forwarded SIGTERM.

## Windows Behavior

Windows lacks POSIX `execve`. `envball-run.exe` always:

1. Decrypts the env payload (using the token).
2. Calls `CreateProcess` to spawn the child with the decrypted env.
3. Waits for the child to exit.
4. Exits with the child's exit code.

Signal-like events from Windows are translated:

| Windows event            | Forwarded to child              |
|--------------------------|---------------------------------|
| Ctrl+C in console        | CTRL_C_EVENT to child group     |
| Console window close     | CTRL_CLOSE_EVENT                |
| `taskkill` (no `/F`)     | CTRL_CLOSE_EVENT (if console)   |
| `taskkill /F`            | TerminateProcess (uncatchable)  |

Console Control Event handling is best-effort. Graceful shutdown
semantics on Windows are weaker than on POSIX, and this is documented
to users.

Windows server containers (Windows-native containers, not Docker
Desktop's Linux-on-Windows) are out of v0.1 scope.

## Testing

Init mode behavior is verified by tests in `internal/runtime/`:

- Unit tests for signal forwarding logic with a mock child.
- Integration tests that spawn `envball-run` as PID 1 inside a minimal
  Docker container and verify:
    - SIGTERM is forwarded and child exits gracefully.
    - Grandchild zombies are reaped.
    - Exit code matches child exit code.
- Cross-platform CI matrix (linux/amd64, linux/arm64, darwin/arm64,
  windows/amd64).

## Flag Reference

    --supervise    Force supervisor mode regardless of PID.
                   Useful for testing supervisor behavior locally.

    --no-init      Force exec-replace regardless of PID.
                   On Linux/macOS, replaces process via syscall.Exec.
                   Emits a warning to stderr if PID 1, since init
                   duties will not be performed.

    (default)      Auto-detect: supervisor when PID 1, exec-replace
                   otherwise (Linux/macOS). Spawn-and-wait (Windows).

## See Also

- `@docs/threat-model.md` — security implications, audit logging
- `@docs/binary-format.md` — what `envball-run` reads before exec
- [tini](https://github.com/krallin/tini),
  [dumb-init](https://github.com/Yelp/dumb-init) — alternative init
  implementations that chain compatibly
