// Command envball is the single binary that multiplexes CLI mode (build,
// init, verify, version) and runtime mode (decrypt-and-exec). Mode is
// chosen by inspecting the running binary's tail: a v1 envball footer
// means "I am a bundled binary; decrypt and exec". No footer means "I
// am the bare CLI; run cobra".
//
// This file is the composition root: the only place allowed to wire
// every adapter into the application services.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/masaoshima/envball/internal/application/build"
	"github.com/masaoshima/envball/internal/application/initapp"
	"github.com/masaoshima/envball/internal/application/run"
	"github.com/masaoshima/envball/internal/application/verify"
	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/execution"
	"github.com/masaoshima/envball/internal/domain/token"
	"github.com/masaoshima/envball/internal/infrastructure/access"
	"github.com/masaoshima/envball/internal/infrastructure/aiignore"
	"github.com/masaoshima/envball/internal/infrastructure/clock"
	"github.com/masaoshima/envball/internal/infrastructure/crypto"
	"github.com/masaoshima/envball/internal/infrastructure/envfile"
	"github.com/masaoshima/envball/internal/infrastructure/format"
	"github.com/masaoshima/envball/internal/infrastructure/process"
	"github.com/masaoshima/envball/internal/interfaceadapter/cli"
)

// These are stamped at link time via -ldflags="-X main.version=... -X main.commit=...".
// Defaults keep `envball version` informative for `go run` / source builds.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	body, hasPayload, err := loadOwnBody()
	if err != nil {
		fmt.Fprintln(os.Stderr, prefixed(err))
		os.Exit(1)
	}
	if hasPayload {
		runtimeMain(body)
		return
	}
	cliMain()
}

// cliMain runs the cobra CLI. Used when the executable carries no payload.
func cliMain() {
	cipher := crypto.NewCipher()
	signer := crypto.NewSigner()
	random := crypto.NewRandom()
	ck := clock.New()
	envFiles := envfile.NewReader()
	codec := format.NewCodec()
	ignores := aiignore.New()

	deps := cli.Deps{
		Build:   build.NewService(cipher, signer, random, ck, envFiles, codec),
		Init:    initapp.NewService(ignores),
		Verify:  verify.NewService(codec, signer),
		Version: version,
		Commit:  commit,
	}
	if err := cli.NewRoot(deps).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, prefixed(err))
		os.Exit(1)
	}
}

// runtimeMain decrypts the bundle and execs the child. Used when the
// executable carries an envball payload.
func runtimeMain(body *bundle.Body) {
	args, err := parseRuntimeArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, prefixed(err))
		os.Exit(2)
	}
	if args.showHelp {
		printRuntimeHelp(os.Stdout)
		return
	}
	if len(args.childArgv) == 0 {
		printRuntimeHelp(os.Stderr)
		os.Exit(2)
	}

	tok, err := loadToken(args.tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, prefixed(err))
		os.Exit(1)
	}

	cipher := crypto.NewCipher()
	signer := crypto.NewSigner()
	codec := format.NewCodec()
	exec := process.New()
	logger := access.New()
	ck := clock.New()
	svc := run.NewService(cipher, signer, codec, exec, logger, ck)

	// No signal handlers here on purpose. The ProcessExecer owns signal
	// handling: in supervisor mode it forwards signals to the child
	// process group; in exec-replace mode the child inherits handlers
	// after execve and main never resumes. Installing parallel handlers
	// here races with the supervisor and causes premature SIGKILL of the
	// child via exec.CommandContext's cancellation policy.
	ctx := context.Background()

	out, err := svc.Run(ctx, run.Input{
		Body:      body,
		Token:     tok,
		ChildArgv: args.childArgv,
		Override:  args.override,
		IsPID1:    process.IsPID1(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, prefixed(err))
		os.Exit(1)
	}
	// Exec-replace would have already replaced the process; reaching
	// here means supervise or spawn returned an exit code to propagate.
	os.Exit(out.ExitCode)
}

// runtimeArgs captures the parsed flag state for runtime mode. We hand-
// roll the parser instead of using cobra here so the user-facing
// `env.ball -- <command>` invocation stays cleanly separated from cobra's
// subcommand machinery, and so unknown flags after `--` get passed
// verbatim to the child.
type runtimeArgs struct {
	tokenFile string
	override  execution.FlagOverride
	childArgv []string
	showHelp  bool
}

func parseRuntimeArgs(argv []string) (runtimeArgs, error) {
	var out runtimeArgs
	i := 1
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			out.childArgv = append(out.childArgv, argv[i+1:]...)
			return out, nil
		case a == "--no-init":
			if out.override != execution.OverrideNone {
				return out, errors.New("--supervise and --no-init are mutually exclusive")
			}
			out.override = execution.OverrideNoInit
			i++
		case a == "--supervise":
			if out.override != execution.OverrideNone {
				return out, errors.New("--supervise and --no-init are mutually exclusive")
			}
			out.override = execution.OverrideSupervise
			i++
		case a == "--token-file":
			if i+1 >= len(argv) {
				return out, errors.New("--token-file requires a path argument")
			}
			out.tokenFile = argv[i+1]
			i += 2
		case strings.HasPrefix(a, "--token-file="):
			out.tokenFile = strings.TrimPrefix(a, "--token-file=")
			i++
		case a == "-h" || a == "--help":
			out.showHelp = true
			i++
		case strings.HasPrefix(a, "-"):
			return out, fmt.Errorf("unknown runtime-mode flag %q (use `--` before the child command)", a)
		default:
			// First non-flag positional starts the child argv. We do
			// not require `--`; this is a convenience for the common
			// case of `env.ball bin/rails server`.
			out.childArgv = append(out.childArgv, argv[i:]...)
			return out, nil
		}
	}
	return out, nil
}

// loadOwnBody returns the parsed bundle body if this executable carries
// an envball payload, and (nil, false, nil) otherwise. Any I/O error
// surfaces as a non-nil err so the caller can fail loudly rather than
// silently switching modes.
func loadOwnBody() (*bundle.Body, bool, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, false, fmt.Errorf("locate own executable: %w", err)
	}
	f, err := os.Open(exePath)
	if err != nil {
		return nil, false, fmt.Errorf("open own executable: %w", err)
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat own executable: %w", err)
	}
	body, err := format.ReadBundle(f, stat.Size())
	if err != nil {
		if errors.Is(err, format.ErrNotEnvball) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return body, true, nil
}

// loadToken resolves a decryption token by deliberately file-only paths,
// in priority order:
//
//  1. --token-file <path>. The literal value "-" or "/dev/stdin" reads
//     the token from os.Stdin (use for pipelines like
//     `pass show envball/prod | env.ball --token-file - -- cmd`).
//  2. $CREDENTIALS_DIRECTORY/envball-token, when systemd has placed a
//     credential there via LoadCredential= / LoadCredentialEncrypted=.
//  3. Sibling file: <executable>.token.
//
// Reading the token from $ENVBALL_TOKEN is intentionally NOT supported.
// Environment-variable delivery would leak via /proc/<pid>/environ,
// ps eww, child-process inheritance, crash dumps, shell history, and
// CI logs — see docs/threat-model.md (T10) and docs/deployment/ for
// non-env distribution recipes.
func loadToken(explicitPath string) (token.Token, error) {
	var siblingPath string
	if explicitPath == "" {
		exePath, err := os.Executable()
		if err != nil {
			return token.Token{}, fmt.Errorf("locate own executable for default token path: %w", err)
		}
		siblingPath = exePath + ".token"
	}
	return resolveToken(explicitPath, os.Getenv("CREDENTIALS_DIRECTORY"), siblingPath, os.Stdin)
}

// resolveToken is the testable inner of loadToken. It takes every input
// (explicit flag, systemd credentials dir, sibling path, stdin reader)
// as a parameter so unit tests can drive each branch without touching
// process state.
func resolveToken(explicitPath, credsDir, siblingPath string, stdin io.Reader) (token.Token, error) {
	if explicitPath != "" {
		if explicitPath == "-" || explicitPath == "/dev/stdin" {
			return readTokenFromReader(stdin)
		}
		return readTokenFromFile(explicitPath)
	}
	if credsDir != "" {
		p := filepath.Join(credsDir, "envball-token")
		if _, err := os.Stat(p); err == nil {
			return readTokenFromFile(p)
		}
	}
	if siblingPath == "" {
		return token.Token{}, errors.New("no token source available; pass --token-file <path>")
	}
	if _, err := os.Stat(siblingPath); errors.Is(err, os.ErrNotExist) {
		return token.Token{}, fmt.Errorf(
			"token file %s not found.\n  pass --token-file <path> (use - for stdin), or place a token file at %s\n  see docs/deployment/ for Docker, Kubernetes, Cloud Run, ECS, and systemd recipes",
			siblingPath, siblingPath,
		)
	}
	return readTokenFromFile(siblingPath)
}

func readTokenFromReader(r io.Reader) (token.Token, error) {
	if r == nil {
		return token.Token{}, errors.New("read token from stdin: no reader available")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return token.Token{}, fmt.Errorf("read token from stdin: %w", err)
	}
	return token.Parse(string(data))
}

func readTokenFromFile(path string) (token.Token, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return token.Token{}, fmt.Errorf("read token file %s: %w", path, err)
	}
	return token.Parse(string(raw))
}

// prefixed renders err for stderr with exactly one leading "envball: "
// regardless of whether the wrapped error already self-prefixed.
func prefixed(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "envball:") || strings.HasPrefix(msg, "envball/") {
		return msg
	}
	return "envball: " + msg
}

func printRuntimeHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: <envball-binary> [--token-file path] [--no-init|--supervise] -- <command> [args...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  --token-file <path>  read the decryption token from this file")
	fmt.Fprintln(w, "                       use \"-\" or \"/dev/stdin\" to read from stdin")
	fmt.Fprintln(w, "                       default search order:")
	fmt.Fprintln(w, "                         1. $CREDENTIALS_DIRECTORY/envball-token (systemd)")
	fmt.Fprintln(w, "                         2. <executable-path>.token")
	fmt.Fprintln(w, "  --no-init            force exec-replace mode even at PID 1")
	fmt.Fprintln(w, "  --supervise          force supervisor mode (signal forwarding + reaping)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Token delivery is file-only by design. Environment-variable delivery")
	fmt.Fprintln(w, "is not supported because it leaks via /proc, ps, child processes,")
	fmt.Fprintln(w, "crash dumps, shell history, and CI logs. See docs/deployment/ for")
	fmt.Fprintln(w, "Docker, Kubernetes, Cloud Run, ECS, and systemd recipes.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  ./env.ball -- bin/rails server")
	fmt.Fprintln(w, "  pass show envball/prod | ./env.ball --token-file - -- node server.js")
	fmt.Fprintln(w, "  ./env.ball --token-file /run/secrets/envball.token -- bin/web")
}
