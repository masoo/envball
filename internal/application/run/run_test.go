package run

import "testing"

func TestMergeEnvStripsSensitiveInheritedKeys(t *testing.T) {
	inherited := []string{
		"PATH=/usr/bin",
		"HOME=/home/dev",
		"ENVBALL_TOKEN=envb_should_not_leak",
		"CREDENTIALS_DIRECTORY=/run/credentials/envball.service",
		"USER=dev",
	}
	bundle := map[string]string{
		"DATABASE_URL": "postgres://example",
	}
	got := mergeEnv(inherited, bundle)

	for _, k := range []string{"ENVBALL_TOKEN", "CREDENTIALS_DIRECTORY"} {
		if _, ok := got[k]; ok {
			t.Errorf("mergeEnv leaked %s to child env: %q", k, got[k])
		}
	}
	for _, k := range []string{"PATH", "HOME", "USER", "DATABASE_URL"} {
		if _, ok := got[k]; !ok {
			t.Errorf("mergeEnv dropped legitimate key %s", k)
		}
	}
}

func TestMergeEnvBundleOverridesInherited(t *testing.T) {
	inherited := []string{
		"API_KEY=inherited-value",
	}
	bundle := map[string]string{
		"API_KEY": "bundle-value",
	}
	got := mergeEnv(inherited, bundle)
	if got["API_KEY"] != "bundle-value" {
		t.Fatalf("bundle should win over inherited: got %q, want %q", got["API_KEY"], "bundle-value")
	}
}

func TestMergeEnvHandlesValuelessAndMalformedEntries(t *testing.T) {
	inherited := []string{
		"EMPTY=",
		"NO_EQUALS_SIGN_AT_ALL",
		"=value-without-key",
		"OK=fine",
	}
	got := mergeEnv(inherited, nil)
	if v, ok := got["EMPTY"]; !ok || v != "" {
		t.Errorf("EMPTY key handling: ok=%v v=%q", ok, v)
	}
	if got["OK"] != "fine" {
		t.Errorf("OK key not retained: %v", got["OK"])
	}
	if _, ok := got["NO_EQUALS_SIGN_AT_ALL"]; ok {
		t.Errorf("malformed entry without = should be skipped")
	}
}
