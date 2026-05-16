// Package initapp scaffolds a new project for envball: ignore files for
// AI tools and VCS, and a sample .env that the developer fills in.
package initapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/masaoshima/envball/internal/domain/port"
)

// Input describes one Init invocation.
type Input struct {
	// ProjectDir is where ignore files and the sample .env land. Empty
	// means current working directory.
	ProjectDir string
	// SampleEnvName is the filename to scaffold (default .env.example).
	// We intentionally do not scaffold .env directly — that file is
	// what envball replaces, so creating it would be self-defeating.
	SampleEnvName string
	// Overwrite controls whether to clobber an existing sample env file.
	Overwrite bool
}

// Output reports what changed on disk.
type Output struct {
	ChangedIgnoreFiles []string
	SampleEnvPath      string
	SampleEnvCreated   bool
}

// Service wires the IgnoreWriter port.
type Service struct {
	ignores port.IgnoreWriter
}

// NewService constructs the init service.
func NewService(w port.IgnoreWriter) *Service { return &Service{ignores: w} }

// Init runs the scaffold. Idempotent: re-running adds nothing new when
// the project is already initialized.
func (svc *Service) Init(in Input) (*Output, error) {
	dir := in.ProjectDir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("envball/initapp: getwd: %w", err)
		}
	}
	if in.SampleEnvName == "" {
		in.SampleEnvName = ".env.example"
	}

	changed, err := svc.ignores.EnsureEntries(dir, defaultIgnoreEntries())
	if err != nil {
		return nil, err
	}

	samplePath := filepath.Join(dir, in.SampleEnvName)
	created, err := writeSampleEnvIfMissing(samplePath, in.Overwrite)
	if err != nil {
		return nil, err
	}

	return &Output{
		ChangedIgnoreFiles: changed,
		SampleEnvPath:      samplePath,
		SampleEnvCreated:   created,
	}, nil
}

// defaultIgnoreEntries is the canonical set of patterns envball asks
// every AI and VCS tool to ignore. Tokens and built binaries must never
// be indexed, committed, or fed to LLMs.
func defaultIgnoreEntries() []string {
	return []string{
		"# Plaintext env files — envball replaces these on purpose",
		".env",
		".env.local",
		".env.*.local",
		"# envball decryption tokens",
		"*.token",
		"# envball built binaries (the encrypted self-extracting executable)",
		"env.bin",
		"env.bin.*",
		"envball-run",
		"envball-run.*",
	}
}

func writeSampleEnvIfMissing(path string, overwrite bool) (bool, error) {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("envball/initapp: stat %s: %w", path, err)
		}
	}
	if err := os.WriteFile(path, []byte(sampleEnvContent), 0o644); err != nil {
		return false, fmt.Errorf("envball/initapp: write %s: %w", path, err)
	}
	return true, nil
}

const sampleEnvContent = `# Sample env file for envball. Fill in real values, then build with:
#   envball build -f .env -o env.bin
# The plaintext .env should NEVER be committed; the envball init step
# adds it to .gitignore and the AI ignore files for you.

# DATABASE_URL=postgres://user:pass@localhost:5432/db
# STRIPE_SECRET_KEY=sk_test_replace_me
`
