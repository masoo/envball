package envset

import "testing"

func TestSetValidatesName(t *testing.T) {
	s := New()
	if err := s.Set("9LEADING_DIGIT", "v"); err == nil {
		t.Fatal("expected error for leading-digit name")
	}
	if err := s.Set("HAS SPACE", "v"); err == nil {
		t.Fatal("expected error for name with space")
	}
	if err := s.Set("OK_NAME", "v"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMergePrefersOverride(t *testing.T) {
	base := New()
	_ = base.Set("FOO", "1")
	_ = base.Set("BAR", "1")
	over := New()
	_ = over.Set("FOO", "2")
	_ = over.Set("BAZ", "3")
	if err := base.Merge(over); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got, _ := base.Get("FOO"); got != "2" {
		t.Fatalf("FOO=%q want 2", got)
	}
	if got, _ := base.Get("BAR"); got != "1" {
		t.Fatalf("BAR=%q want 1", got)
	}
	if got, _ := base.Get("BAZ"); got != "3" {
		t.Fatalf("BAZ=%q want 3", got)
	}
	if base.Len() != 3 {
		t.Fatalf("len=%d want 3", base.Len())
	}
}

func TestSetRejectsNULValue(t *testing.T) {
	s := New()
	if err := s.Set("X", "a\x00b"); err == nil {
		t.Fatal("expected error for NUL in value")
	}
}
