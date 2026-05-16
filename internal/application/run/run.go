// Package run orchestrates the DecryptAndExec use case for runtime mode:
// read the running binary's body, decrypt with the supplied token, then
// hand control to the child process per the resolved ExecutionMode.
package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/oklog/ulid/v2"

	"github.com/masaoshima/envball/internal/domain/bundle"
	"github.com/masaoshima/envball/internal/domain/execution"
	"github.com/masaoshima/envball/internal/domain/port"
	"github.com/masaoshima/envball/internal/domain/token"
)

// Input describes one DecryptAndExec invocation.
type Input struct {
	// Body is the parsed (and, if signed, already verified) bundle body
	// from the running binary. The CLI layer obtains it via format.
	Body *bundle.Body
	// Token is the parsed decryption token.
	Token token.Token
	// ChildArgv is the command and arguments the child should run.
	ChildArgv []string
	// Override carries --supervise / --no-init from the CLI.
	Override execution.FlagOverride
	// IsPID1 lets the application layer accept a host fact from the
	// infrastructure side without itself calling os.Getpid (kept pure-ish).
	IsPID1 bool
}

// Output is what DecryptAndExec returns. For exec-replace mode the
// process never returns; the struct is populated only for spawn/supervise
// paths.
type Output struct {
	ExitCode int
	Mode     execution.Mode
}

// Service wires the runtime decision + exec ports.
type Service struct {
	cipher port.Cipher
	signer port.Signer
	codec  port.BundleCodec
	exec   port.ProcessExecer
	access port.AccessLogger
	clock  port.Clock
}

// NewService constructs the run service from its injected ports.
func NewService(c port.Cipher, s port.Signer, cd port.BundleCodec, ex port.ProcessExecer, al port.AccessLogger, ck port.Clock) *Service {
	return &Service{cipher: c, signer: s, codec: cd, exec: ex, access: al, clock: ck}
}

// Run decrypts the body and hands off to the child.
func (svc *Service) Run(ctx context.Context, in Input) (*Output, error) {
	if in.Body == nil {
		return nil, errors.New("envball/run: nil body")
	}
	if len(in.ChildArgv) == 0 {
		return nil, errors.New("envball/run: no child command supplied (use: envball-run -- <command>)")
	}

	if in.Body.IsSigned() {
		sigInput, err := svc.codec.EncodeBodyForSigning(in.Body)
		if err != nil {
			return nil, err
		}
		if err := svc.signer.Verify(in.Body.SignerPubKey, sigInput, in.Body.Signature); err != nil {
			return nil, err
		}
	}

	envMap, err := svc.decryptEnv(in.Body, in.Token)
	if err != nil {
		return nil, err
	}

	host := execution.Host{OS: runtime.GOOS, IsPID1: in.IsPID1}
	mode := execution.Resolve(host, in.Override)
	if execution.NoInitAtPID1(host, in.Override) {
		fmt.Fprintln(os.Stderr, "envball: warning: --no-init at PID 1; signal forwarding and zombie reaping will not happen")
	}

	envSlice := envMapToSlice(mergeWithCurrentEnv(envMap))

	_ = svc.access.LogRun(port.AccessEntry{
		Timestamp: svc.clock.Now(),
		BinaryID:  binaryIDString(in.Body.BinaryID),
		Cwd:       cwdOrEmpty(),
		ChildArgv: in.ChildArgv,
		ParentPID: os.Getppid(),
		Mode:      mode.String(),
	})

	switch mode {
	case execution.ModeExecReplace:
		if err := svc.exec.Exec(ctx, in.ChildArgv, envSlice); err != nil {
			return nil, err
		}
		return &Output{Mode: mode}, nil // unreachable on success
	case execution.ModeSupervisor:
		code, err := svc.exec.Supervise(ctx, in.ChildArgv, envSlice)
		if err != nil {
			return nil, err
		}
		return &Output{ExitCode: code, Mode: mode}, nil
	case execution.ModeWindowsSpawn:
		code, err := svc.exec.Spawn(ctx, in.ChildArgv, envSlice)
		if err != nil {
			return nil, err
		}
		return &Output{ExitCode: code, Mode: mode}, nil
	default:
		return nil, fmt.Errorf("envball/run: unresolved execution mode")
	}
}

func (svc *Service) decryptEnv(body *bundle.Body, tok token.Token) (map[string]string, error) {
	key, err := svc.cipher.DeriveKey(tok.Random(), body.BinaryID)
	if err != nil {
		return nil, fmt.Errorf("envball/run: derive key: %w", err)
	}
	aad, err := svc.codec.EncodeAAD(body.Version, body.Scheme, body.BinaryID)
	if err != nil {
		return nil, err
	}
	plaintext, err := svc.cipher.Decrypt(key, body.Nonce, aad, body.EncryptedEnv)
	if err != nil {
		return nil, err
	}
	envMap, err := svc.codec.DecodeEnvMap(plaintext)
	if err != nil {
		return nil, err
	}
	return envMap, nil
}

// sensitiveInheritedEnvKeys lists env vars that must never leak to the
// child process from envball's own environment. ENVBALL_TOKEN is treated
// as a token in case some caller still tries to deliver it via env (the
// CLI itself never reads it; see cmd/envball/main.go). CREDENTIALS_DIRECTORY
// hides systemd's credentials directory pointer from the child, so the
// child cannot opportunistically read sibling credentials (e.g. the
// envball-token file) without an explicit, hard-coded path.
var sensitiveInheritedEnvKeys = map[string]struct{}{
	"ENVBALL_TOKEN":         {},
	"CREDENTIALS_DIRECTORY": {},
}

// mergeWithCurrentEnv layers the bundle env on top of the inherited
// process env. Inherited PATH, HOME, USER, locale, etc. survive; bundle
// values override identically-named inherited vars. Entries listed in
// sensitiveInheritedEnvKeys are dropped before forwarding to the child.
func mergeWithCurrentEnv(bundleEnv map[string]string) map[string]string {
	return mergeEnv(os.Environ(), bundleEnv)
}

// mergeEnv is the side-effect-free core of mergeWithCurrentEnv, factored
// out so unit tests can drive it without touching real process state.
func mergeEnv(inherited []string, bundleEnv map[string]string) map[string]string {
	out := make(map[string]string, len(bundleEnv)+len(inherited))
	for _, kv := range inherited {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				key := kv[:i]
				if _, drop := sensitiveInheritedEnvKeys[key]; drop {
					break
				}
				out[key] = kv[i+1:]
				break
			}
		}
	}
	for k, v := range bundleEnv {
		out[k] = v
	}
	return out
}

func envMapToSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

func binaryIDString(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	var id ulid.ULID
	copy(id[:], raw)
	return id.String()
}

func cwdOrEmpty() string {
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return ""
}
