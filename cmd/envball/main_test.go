package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masaoshima/envball/internal/domain/token"
)

func mustToken(t *testing.T) (token.Token, string) {
	t.Helper()
	raw := bytes.Repeat([]byte{0x7E}, token.RandomLen)
	tok, err := token.New(raw)
	if err != nil {
		t.Fatalf("token.New: %v", err)
	}
	return tok, tok.String()
}

func TestResolveTokenReadsStdinForDashFlag(t *testing.T) {
	want, s := mustToken(t)
	got, err := resolveToken("-", "", "", strings.NewReader(s))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if !bytes.Equal(got.Random(), want.Random()) {
		t.Fatalf("token mismatch from stdin")
	}
}

func TestResolveTokenReadsStdinForDevStdin(t *testing.T) {
	want, s := mustToken(t)
	got, err := resolveToken("/dev/stdin", "", "", strings.NewReader(s))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if !bytes.Equal(got.Random(), want.Random()) {
		t.Fatalf("token mismatch from /dev/stdin alias")
	}
}

func TestResolveTokenReadsCredentialsDirectory(t *testing.T) {
	dir := t.TempDir()
	want, s := mustToken(t)
	if err := os.WriteFile(filepath.Join(dir, "envball-token"), []byte(s), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}
	got, err := resolveToken("", dir, filepath.Join(dir, "missing-sibling"), nil)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if !bytes.Equal(got.Random(), want.Random()) {
		t.Fatalf("token mismatch from credentials directory")
	}
}

func TestResolveTokenFallsBackToSiblingFile(t *testing.T) {
	dir := t.TempDir()
	sibling := filepath.Join(dir, "env.bin.token")
	want, s := mustToken(t)
	if err := os.WriteFile(sibling, []byte(s), 0o600); err != nil {
		t.Fatalf("write sibling file: %v", err)
	}
	got, err := resolveToken("", "", sibling, nil)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if !bytes.Equal(got.Random(), want.Random()) {
		t.Fatalf("token mismatch from sibling file")
	}
}

func TestResolveTokenIgnoresEnvballTokenEnvVar(t *testing.T) {
	// Even if a stale ENVBALL_TOKEN is set in the test process env, it must
	// not be consulted: file-only delivery is the design contract.
	t.Setenv("ENVBALL_TOKEN", "envb_should_be_ignored")
	_, err := resolveToken("", "", filepath.Join(t.TempDir(), "absent"), nil)
	if err == nil {
		t.Fatalf("resolveToken: expected error when no file source is available, got nil")
	}
	if !strings.Contains(err.Error(), "token file") {
		t.Fatalf("resolveToken error should describe missing file, got %q", err.Error())
	}
}

func TestResolveTokenMissingSiblingReturnsHelpfulError(t *testing.T) {
	sibling := filepath.Join(t.TempDir(), "missing.token")
	_, err := resolveToken("", "", sibling, nil)
	if err == nil {
		t.Fatalf("resolveToken: expected error for missing sibling, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not found") {
		t.Fatalf("error should say 'not found': %q", msg)
	}
	if !strings.Contains(msg, "--token-file") {
		t.Fatalf("error should mention --token-file: %q", msg)
	}
	if !strings.Contains(msg, "docs/deployment") {
		t.Fatalf("error should point to docs/deployment: %q", msg)
	}
}

func TestResolveTokenStdinWithoutReader(t *testing.T) {
	_, err := resolveToken("-", "", "", nil)
	if err == nil {
		t.Fatalf("resolveToken: expected error when stdin reader is nil, got nil")
	}
}

func TestResolveTokenExplicitFileTakesPrecedenceOverCredsDir(t *testing.T) {
	credsDir := t.TempDir()
	// Write a different valid token to credentials directory; resolveToken
	// must not look at it when an explicit --token-file is supplied.
	raw := bytes.Repeat([]byte{0x11}, token.RandomLen)
	credsTok, _ := token.New(raw)
	if err := os.WriteFile(filepath.Join(credsDir, "envball-token"), []byte(credsTok.String()), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	explicit := filepath.Join(t.TempDir(), "explicit.token")
	want, s := mustToken(t)
	if err := os.WriteFile(explicit, []byte(s), 0o600); err != nil {
		t.Fatalf("write explicit file: %v", err)
	}

	got, err := resolveToken(explicit, credsDir, "", nil)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if !bytes.Equal(got.Random(), want.Random()) {
		t.Fatalf("explicit --token-file should win over credentials directory")
	}
}

func TestResolveTokenExplicitFileMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.token")
	_, err := resolveToken(missing, "", "", nil)
	if err == nil {
		t.Fatalf("resolveToken: expected error for missing explicit file")
	}
	// The error wraps os.ErrNotExist so callers/tests can distinguish.
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error should wrap os.ErrNotExist, got %v", err)
	}
}
