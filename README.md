# envball

envball is a Go CLI that packs environment variables into a self-contained, encrypted executable.

Running the generated binary decrypts env values in memory only and then execs your child command. The decryption token is delivered out-of-band as a file — it is never embedded in the binary and never read from an environment variable.

envball is designed around these principles:

- No runtime cloud dependency for decryption/execution.
- No plaintext `.env` recreation on disk.
- Token is never embedded in the binary.
- Env variable **names and values are both encrypted** (names live inside the encrypted payload).
- AI-resistant by default: tooling that walks the filesystem cannot extract env without holding the separate token file.

## Why

Teams often pass around plaintext `.env` files, which leak easily to logs, git history, screenshots, and AI tooling.

envball replaces this with:

- An encrypted, self-extracting bundle binary
- A separate token file (default: `<binary>.token`)

Without the token, the bundle cannot be decrypted.

## Quick Start

1. Build the CLI:

   ```
   task build
   # or: go build -trimpath -ldflags="-buildid=" -o bin/envball ./cmd/envball
   ```

2. Initialize ignore files and a sample env in your project:

   ```
   ./bin/envball init
   ```

   This writes/updates `.gitignore`, `.aiignore`, `.cursorignore`, `.continueignore` and scaffolds `.env.example`.

3. Build an encrypted runnable bundle:

   ```
   ./bin/envball build -f .env -o env.bin
   ```

   This writes both `env.bin` (mode 0755) and `env.bin.token` (mode 0600). **Save the token in your password manager immediately** — losing it makes the binary unreadable.

4. Verify metadata/signature (no token required):

   ```
   ./bin/envball verify env.bin
   ```

5. Run with the decrypted env injected into a child process:

   ```
   ./env.bin -- env
   ./env.bin -- bin/rails server
   ```

   With no `--token-file`, the runtime looks for `env.bin.token` next to the binary.

## Token Resolution Order (runtime)

Token delivery is **file-only by design**. Environment-variable delivery (e.g. `ENVBALL_TOKEN`) is intentionally not supported because it leaks via `/proc/<pid>/environ`, `ps eww`, child-process inheritance, crash dumps, shell history, and CI logs — see [docs/threat-model.md](docs/threat-model.md) (T10).

When running an envball bundle, the token source is resolved in this order:

1. `--token-file <path>` — explicit flag. The literal value `-` or `/dev/stdin` reads the token from standard input (useful for pipelines such as `pass show envball/prod | ./env.bin --token-file - -- cmd`).
2. `$CREDENTIALS_DIRECTORY/envball-token` — systemd credentials directory (set via `LoadCredential=` / `LoadCredentialEncrypted=`).
3. `<executable>.token` — sibling token file next to the bundle binary.

The runtime also strips `CREDENTIALS_DIRECTORY` from the inherited env before exec'ing the child, so the credential path does not leak into the child process.

## Runtime Flags

```
<envball-binary> [--token-file <path>] [--no-init | --supervise] -- <command> [args...]
```

- `--token-file <path>` — read the decryption token from this file (`-` or `/dev/stdin` for stdin).
- `--no-init` — force exec-replace mode even at PID 1.
- `--supervise` — force supervisor mode (signal forwarding + zombie reaping). Default is auto: supervisor when the runtime detects PID 1 on Linux, otherwise exec-replace. See [docs/init-mode.md](docs/init-mode.md).
- `-h`, `--help` — show the runtime usage banner.

Anything after `--` is passed verbatim to the child command.

## Commands

- `envball init`
  - Adds ignore rules to `.gitignore`, `.aiignore`, `.cursorignore`, `.continueignore` (token files, built binaries, `.env`).
  - Scaffolds `.env.example` (skipped if one already exists; use `--overwrite` to replace).
  - Flags: `-C/--dir`, `--sample`, `--overwrite`.

- `envball build -f <env-file>... -o <output>`
  - Reads and merges one or more env files (later files override earlier ones).
  - Generates a fresh per-build key and Ed25519 signing key, encrypts the env map (names + values), and writes a self-extracting executable.
  - Emits `<output>` (mode 0755) and `<output>.token` (mode 0600) by default.
  - Flags: `-f/--env-file` (repeatable), `-o/--output`, `--token-out`, `--silent`, `--target-os`, `--target-arch`.

- `envball verify <binary>`
  - Reads bundle metadata without decrypting (format version, scheme, binary id, built_at, target, signer pubkey).
  - Validates the bundle format and verifies the Ed25519 signature when present. No token required.

- `envball version`
  - Prints version, commit, and Go runtime info.

## Security Model (v0.1)

- The runtime path (decrypt-and-exec) makes no network calls.
- Decryption is local-only and token-gated; the token is never embedded in the binary.
- No subcommand or flag prints, dumps, exports, or writes the decrypted env. The only sink is `execve` of the child process.
- Env variable **names are encrypted alongside values** — unencrypted bundle metadata reveals nothing about your stack.
- Access logging (when enabled) records execution metadata only (binary id, time, cwd, child command, parent PID) — never secret values or env names.
- The runtime strips `CREDENTIALS_DIRECTORY` from the inherited env before exec'ing the child.

For details:

- [docs/binary-format.md](docs/binary-format.md) — byte-level format, CBOR schema, KDF, signature
- [docs/threat-model.md](docs/threat-model.md) — defended threats, residual risks, comparisons
- [docs/init-mode.md](docs/init-mode.md) — PID 1 detection, supervisor behavior, Docker integration

## Development

Common tasks (via [Task](https://taskfile.dev)):

- `task tidy` — sync `go.mod` / `go.sum`
- `task vet` — `go vet ./...`
- `task test` — `go test ./... -race -count=1`
- `task lint` — `golangci-lint run`
- `task build` — build `./bin/envball` for the host platform
- `task build:all` — cross-build every v0.1 target
- `task smoke` — end-to-end: init → build envball → build env.bin → decrypt-and-exec
- `task ci` — what CI runs (`vet` + `test` + `build`)

Direct equivalents:

```
go build -trimpath -ldflags="-buildid=" -o bin/envball ./cmd/envball
go test ./... -race -count=1
golangci-lint run
```

Reproducible-build flags (`-trimpath`, `-ldflags="-buildid="`, pinned Go toolchain via `go.mod`) are mandatory and applied by every Taskfile target.

## Platform targets (v0.1)

| Platform        | Support     | Notes                                |
|-----------------|-------------|--------------------------------------|
| linux/amd64     | first-class | Primary prod target (Docker, CI)     |
| linux/arm64     | first-class | Graviton, ARM servers, Docker        |
| darwin/arm64    | first-class | Apple Silicon Mac dev                |
| darwin/amd64    | first-class | Intel Mac dev                        |
| windows/amd64   | dev support | Spawn-and-wait; no init mode         |

WSL2 runs Linux binaries — covered by linux/amd64.

## Cloud roadmap note

v0.1 keeps build and runtime local-only. A future cloud distribution workflow (v0.2+) can be added while preserving local decryption and the build-is-local / token-is-separate guarantees.

## License

Apache License 2.0. See [LICENSE](LICENSE).
