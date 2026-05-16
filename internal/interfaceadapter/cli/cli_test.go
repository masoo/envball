package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/masaoshima/envball/internal/application/build"
	"github.com/masaoshima/envball/internal/application/initapp"
	"github.com/masaoshima/envball/internal/application/verify"
	"github.com/masaoshima/envball/internal/infrastructure/aiignore"
	"github.com/masaoshima/envball/internal/infrastructure/clock"
	"github.com/masaoshima/envball/internal/infrastructure/crypto"
	"github.com/masaoshima/envball/internal/infrastructure/envfile"
	"github.com/masaoshima/envball/internal/infrastructure/format"
)

func newDeps() Deps {
	return Deps{
		Build: build.NewService(
			crypto.NewCipher(),
			crypto.NewSigner(),
			crypto.NewRandom(),
			clock.New(),
			envfile.NewReader(),
			format.NewCodec(),
		),
		Init:    initapp.NewService(aiignore.New()),
		Verify:  verify.NewService(format.NewCodec(), crypto.NewSigner()),
		Version: "1.2.3",
		Commit:  "abc1234",
	}
}

func run(t *testing.T, args []string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := NewRoot(newDeps())
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestRootExposesAllSubcommands(t *testing.T) {
	cmd := NewRoot(newDeps())
	want := []string{"init", "build", "verify", "version"}
	got := map[string]bool{}
	for _, c := range cmd.Commands() {
		got[c.Name()] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("subcommand %q missing", w)
		}
	}
}

func TestVersionCommandPrintsLinkTimeStrings(t *testing.T) {
	stdout, _, err := run(t, []string{"version"})
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(stdout, "1.2.3") {
		t.Errorf("output missing version: %q", stdout)
	}
	if !strings.Contains(stdout, "abc1234") {
		t.Errorf("output missing commit: %q", stdout)
	}
}

func TestInitCommandScaffoldsDirectory(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := run(t, []string{"init", "-C", dir})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stdout, "wrote sample env") {
		t.Errorf("init output missing scaffold message: %q", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err != nil {
		t.Errorf("init did not create .gitignore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.example")); err != nil {
		t.Errorf("init did not create .env.example: %v", err)
	}
}

func TestInitCommandSecondRunReportsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := run(t, []string{"init", "-C", dir}); err != nil {
		t.Fatalf("first init: %v", err)
	}
	stdout, _, err := run(t, []string{"init", "-C", dir})
	if err != nil {
		t.Fatalf("second init: %v", err)
	}
	if !strings.Contains(stdout, "already up to date") {
		t.Errorf("second init should report idempotency, got %q", stdout)
	}
	if !strings.Contains(stdout, "already exists") {
		t.Errorf("second init should report sample env already exists, got %q", stdout)
	}
}

func TestBuildCommandRequiresEnvFile(t *testing.T) {
	_, _, err := run(t, []string{"build", "-o", filepath.Join(t.TempDir(), "out.bin")})
	if err == nil {
		t.Fatalf("build without -f should fail")
	}
	if !strings.Contains(err.Error(), "-f") {
		t.Errorf("error should mention -f flag, got %v", err)
	}
}

func TestBuildCommandRequiresOutput(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("X=1\n"), 0o600); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	cmd := NewRoot(newDeps())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"build", "-f", envPath, "-o", ""})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("build with empty -o should fail")
	}
}

func TestVerifyCommandRequiresExactlyOneArg(t *testing.T) {
	cmd := NewRoot(newDeps())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"verify"})
	if err := cmd.Execute(); err == nil {
		t.Errorf("verify without args should fail")
	}
}

func TestVerifyCommandRejectsNonEnvballFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-bundle")
	if err := os.WriteFile(path, []byte("not envball"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, _, err := run(t, []string{"verify", path})
	if err == nil {
		t.Fatalf("verify on junk file should fail")
	}
	if !errors.Is(err, format.ErrNotEnvball) {
		// CLI may wrap; allow message-level check too
		if !strings.Contains(err.Error(), "not an envball binary") {
			t.Errorf("error should signal not-envball, got %v", err)
		}
	}
}

func TestSubcommandsHaveShortDescriptions(t *testing.T) {
	cmd := NewRoot(newDeps())
	cmd.Commands()
	for _, c := range cmd.Commands() {
		if c.Short == "" {
			t.Errorf("subcommand %q has empty Short description", c.Name())
		}
	}
}

func TestRootSilencesUsageAndErrorsOnFailure(t *testing.T) {
	// SilenceUsage means a returned error from RunE does NOT cause cobra
	// to print the full usage banner — important for clean stderr output.
	cmd := NewRoot(newDeps())
	if !cmd.SilenceUsage {
		t.Errorf("root should set SilenceUsage = true")
	}
	if !cmd.SilenceErrors {
		t.Errorf("root should set SilenceErrors = true (main.go prints them)")
	}
}

// Ensure that NewRoot does not panic with a zero Deps (defensive sanity).
func TestNewRootDoesNotPanicWithZeroDeps(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewRoot(zero Deps) panicked: %v", r)
		}
	}()
	cmd := NewRoot(Deps{})
	if cmd == nil {
		t.Fatalf("NewRoot returned nil")
	}
	// We don't run RunE — those will deference nil services. The
	// construction step alone must be safe.
	_ = cmd
}

// helperCommand resolves a subcommand by name for direct invocation in
// future tests; kept as a small utility even though it's currently unused
// to keep the file's intent visible.
func helperCommand(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

var _ = helperCommand // suppress "declared and not used" in case of refactor
