package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/masaoshima/envball/internal/application/build"
	"github.com/masaoshima/envball/internal/domain/bundle"
)

func newBuildCommand(d Deps) *cobra.Command {
	var (
		envFiles      []string
		outputPath    string
		tokenOutPath  string
		tokenSilent   bool
		targetOS      string
		targetArch    string
	)
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Encrypt .env files into a self-extracting executable.",
		Long: "Reads one or more .env files, generates a fresh decryption token,\n" +
			"encrypts the env under that token, and writes a self-extracting\n" +
			"executable. The token is written to <output>.token by default;\n" +
			"protect it as you would a private key.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(envFiles) == 0 {
				return errors.New("envball build: at least one -f/--env-file is required")
			}
			if outputPath == "" {
				return errors.New("envball build: -o/--output is required")
			}

			stubBytes, err := loadStubBytes()
			if err != nil {
				return err
			}

			result, err := d.Build.Build(build.Input{
				EnvFiles:  envFiles,
				StubBytes: stubBytes,
				Target:    bundle.Target{OS: targetOS, Arch: targetArch},
			})
			if err != nil {
				return err
			}

			if err := writeBinary(outputPath, result.BinaryBytes); err != nil {
				return err
			}

			tokenPath := tokenOutPath
			if tokenPath == "" {
				tokenPath = outputPath + ".token"
			}
			if err := writeTokenFile(tokenPath, result.Token.String()); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "envball: wrote %s (%d bytes)\n", outputPath, len(result.BinaryBytes))
			fmt.Fprintf(cmd.OutOrStdout(), "envball: wrote %s (mode 0600)\n", tokenPath)
			if !tokenSilent {
				fmt.Fprintln(cmd.OutOrStdout(), "envball: store the token in your password manager NOW. Losing it makes the binary unreadable.")
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&envFiles, "env-file", "f", nil, "path to a .env file (repeatable; later files override earlier ones)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "env.ball", "output executable path")
	cmd.Flags().StringVar(&tokenOutPath, "token-out", "", "where to write the token file (default: <output>.token)")
	cmd.Flags().BoolVar(&tokenSilent, "silent", false, "suppress the post-build 'save the token' reminder")
	cmd.Flags().StringVar(&targetOS, "target-os", runtime.GOOS, "target OS label embedded in metadata (default: host)")
	cmd.Flags().StringVar(&targetArch, "target-arch", runtime.GOARCH, "target arch label embedded in metadata (default: host)")
	return cmd
}

// loadStubBytes returns the running envball executable with any envball
// payload stripped, so it can be reused as a clean stub. The v0.1 build
// pipeline uses this in place of pre-built stubs/<os>-<arch> files.
func loadStubBytes() ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("envball build: locate own executable: %w", err)
	}
	// Resolve symlinks so we don't end up with a tiny shim wrapper.
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		return nil, fmt.Errorf("envball build: read own executable: %w", err)
	}
	return bundle.StripPayload(raw), nil
}

func writeBinary(path string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("envball build: mkdir parent of %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, contents, 0o755); err != nil {
		return fmt.Errorf("envball build: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("envball build: chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("envball build: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func writeTokenFile(path, tokenString string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("envball build: mkdir parent of %s: %w", path, err)
	}
	content := []byte(bundle.TokenFileHeader + tokenString + "\n")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("envball build: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("envball build: write %s: %w", path, err)
	}
	return nil
}
