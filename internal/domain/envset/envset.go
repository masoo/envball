// Package envset models the in-memory representation of an environment
// variable map prior to encryption. It contains no I/O — file parsing
// lives in infrastructure/envfile, which produces EnvSet values.
package envset

import (
	"errors"
	"sort"
	"strings"
	"unicode"
)

var (
	ErrEmptyName    = errors.New("envball: env var name cannot be empty")
	ErrInvalidName  = errors.New("envball: env var name must start with a letter or '_' and contain only [A-Za-z0-9_]")
	ErrNULInValue   = errors.New("envball: env var value contains a NUL byte, which the OS cannot represent")
)

// EnvVar is a single name/value pair destined for the encrypted payload.
type EnvVar struct {
	Name  string
	Value string
}

// Validate enforces the POSIX-compatible name rule and the OS-level
// constraint that env values may not contain NUL.
func (v EnvVar) Validate() error {
	if v.Name == "" {
		return ErrEmptyName
	}
	for i, r := range v.Name {
		if i == 0 {
			if !isLetter(r) && r != '_' {
				return ErrInvalidName
			}
			continue
		}
		if !isLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return ErrInvalidName
		}
	}
	if strings.ContainsRune(v.Value, 0) {
		return ErrNULInValue
	}
	return nil
}

func isLetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// EnvSet is an ordered, de-duplicated set of EnvVars. Order is preserved
// for deterministic CBOR output; later entries with the same name win on
// merge.
type EnvSet struct {
	order []string
	byKey map[string]string
}

// New returns an empty EnvSet ready for Set / Merge.
func New() *EnvSet {
	return &EnvSet{byKey: map[string]string{}}
}

// Set inserts or replaces a single variable, preserving first-insertion
// order for deterministic output.
func (s *EnvSet) Set(name, value string) error {
	v := EnvVar{Name: name, Value: value}
	if err := v.Validate(); err != nil {
		return err
	}
	if _, ok := s.byKey[name]; !ok {
		s.order = append(s.order, name)
	}
	s.byKey[name] = value
	return nil
}

// Get returns the value for name and whether it was set.
func (s *EnvSet) Get(name string) (string, bool) {
	v, ok := s.byKey[name]
	return v, ok
}

// Len reports the number of variables in the set.
func (s *EnvSet) Len() int { return len(s.order) }

// Names returns the variable names in insertion order.
func (s *EnvSet) Names() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// SortedNames returns the variable names in lexical order. Used when
// stable output is needed for human-readable listings.
func (s *EnvSet) SortedNames() []string {
	out := s.Names()
	sort.Strings(out)
	return out
}

// AsMap returns a copy of the underlying name→value map. Mutating the
// returned map does not affect the EnvSet.
func (s *EnvSet) AsMap() map[string]string {
	out := make(map[string]string, len(s.byKey))
	for k, v := range s.byKey {
		out[k] = v
	}
	return out
}

// Merge applies override on top of s in place: keys present in override
// replace those in s; keys only in override are appended. This implements
// the "base + overrides" layered merge domain rule.
func (s *EnvSet) Merge(override *EnvSet) error {
	if override == nil {
		return nil
	}
	for _, name := range override.order {
		if err := s.Set(name, override.byKey[name]); err != nil {
			return err
		}
	}
	return nil
}
