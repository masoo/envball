package initapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masaoshima/envball/internal/infrastructure/aiignore"
)

func newService() *Service {
	return NewService(aiignore.New())
}

func TestInitCreatesIgnoreFilesAndSampleEnv(t *testing.T) {
	dir := t.TempDir()
	out, err := newService().Init(Input{ProjectDir: dir})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !out.SampleEnvCreated {
		t.Errorf("SampleEnvCreated = false; want true")
	}
	if out.SampleEnvPath != filepath.Join(dir, ".env.example") {
		t.Errorf("SampleEnvPath = %q", out.SampleEnvPath)
	}
	// All managed ignore files should now exist.
	for _, name := range aiignore.ManagedFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("ignore file %s not created: %v", name, err)
		}
	}
}

func TestInitIgnoreFilesContainExpectedEntries(t *testing.T) {
	dir := t.TempDir()
	if _, err := newService().Init(Input{ProjectDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	s := string(content)
	required := []string{".env", ".env.local", "*.token", "env.bin"}
	for _, want := range required {
		if !strings.Contains(s, want) {
			t.Errorf(".gitignore missing %q\n%s", want, s)
		}
	}
}

func TestInitSampleEnvDoesNotContainRealEnvFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := newService().Init(Input{ProjectDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Specifically, init should NEVER create .env directly — that file is
	// what envball replaces.
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Errorf(".env should NOT be created by init; got stat err = %v", err)
	}
}

func TestInitSampleEnvIsValidCommentedTemplate(t *testing.T) {
	dir := t.TempDir()
	out, _ := newService().Init(Input{ProjectDir: dir})
	content, err := os.ReadFile(out.SampleEnvPath)
	if err != nil {
		t.Fatalf("read sample env: %v", err)
	}
	s := string(content)
	// Every non-blank line must start with '#' so the template is safe
	// to commit and won't accidentally set anything when sourced.
	for i, line := range strings.Split(s, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if !strings.HasPrefix(trim, "#") {
			t.Errorf("sample line %d is not a comment: %q", i+1, line)
		}
	}
}

func TestInitIsIdempotentWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	first, _ := newService().Init(Input{ProjectDir: dir})
	if !first.SampleEnvCreated {
		t.Fatalf("first call should create sample env")
	}
	second, err := newService().Init(Input{ProjectDir: dir})
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	if second.SampleEnvCreated {
		t.Errorf("second call should NOT recreate the sample env")
	}
	if len(second.ChangedIgnoreFiles) != 0 {
		t.Errorf("second call should leave ignore files alone, got %v", second.ChangedIgnoreFiles)
	}
}

func TestInitOverwriteForcesSampleEnvRewrite(t *testing.T) {
	dir := t.TempDir()
	samplePath := filepath.Join(dir, ".env.example")
	if err := os.WriteFile(samplePath, []byte("pre-existing user content"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := newService().Init(Input{ProjectDir: dir, Overwrite: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !out.SampleEnvCreated {
		t.Errorf("Overwrite=true should report SampleEnvCreated = true")
	}
	content, _ := os.ReadFile(samplePath)
	if strings.Contains(string(content), "pre-existing user content") {
		t.Errorf("Overwrite=true should replace user content, got %q", string(content))
	}
}

func TestInitHonorsCustomSampleName(t *testing.T) {
	dir := t.TempDir()
	out, err := newService().Init(Input{ProjectDir: dir, SampleEnvName: ".env.sample"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if out.SampleEnvPath != filepath.Join(dir, ".env.sample") {
		t.Errorf("SampleEnvPath = %q", out.SampleEnvPath)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.sample")); err != nil {
		t.Errorf("custom sample env not created: %v", err)
	}
}

func TestInitDefaultsToCwdWhenProjectDirEmpty(t *testing.T) {
	dir := t.TempDir()
	saved, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(saved) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if _, err := newService().Init(Input{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.example")); err != nil {
		t.Errorf(".env.example not created in cwd: %v", err)
	}
}
