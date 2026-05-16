package clock

import (
	"testing"
	"time"
)

func TestNowReturnsUTC(t *testing.T) {
	got := New().Now()
	if got.Location() != time.UTC {
		t.Errorf("Now() location = %s, want UTC", got.Location())
	}
}

func TestNowIsRecent(t *testing.T) {
	before := time.Now().Add(-time.Second).UTC()
	got := New().Now()
	after := time.Now().Add(time.Second).UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("Now() = %v outside [%v, %v]", got, before, after)
	}
}

func TestNowMonotonicAcrossCalls(t *testing.T) {
	a := New().Now()
	time.Sleep(2 * time.Millisecond)
	b := New().Now()
	if !b.After(a) && !b.Equal(a) {
		t.Errorf("Now() not monotonically non-decreasing: a=%v b=%v", a, b)
	}
}
