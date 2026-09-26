package cron

import (
	"testing"
	"time"
)

func TestParseAndMatch(t *testing.T) {
	s, err := Parse("0 22 * * 6")
	if err != nil {
		t.Fatal(err)
	}
	sat := time.Date(2026, 9, 26, 22, 0, 0, 0, time.UTC) // a Saturday
	if !s.Matches(sat) || s.Matches(sat.Add(time.Minute)) || s.Matches(sat.Add(24*time.Hour)) {
		t.Fatal("weekday match")
	}
	s, _ = Parse("*/15 9-17 1,15 jan-mar mon-fri")
	if !s.Matches(time.Date(2026, 2, 15, 9, 45, 0, 0, time.UTC)) {
		t.Fatal("list/range/step")
	}
	// dom OR dow when both restricted: Feb 16 2026 is a Monday.
	if !s.Matches(time.Date(2026, 2, 16, 9, 0, 0, 0, time.UTC)) {
		t.Fatal("dom||dow")
	}
	if s.Matches(time.Date(2026, 2, 14, 9, 0, 0, 0, time.UTC)) { // Saturday the 14th
		t.Fatal("neither dom nor dow")
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "a * * * *", "*/0 * * * *"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestWindowOpen(t *testing.T) {
	// Saturday 22:00 America/Los_Angeles for 6 h.
	la, _ := time.LoadLocation("America/Los_Angeles")
	start := time.Date(2026, 9, 26, 22, 0, 0, 0, la)
	cases := []struct {
		at   time.Time
		want bool
	}{
		{start.Add(-10 * time.Minute), false},
		{start.Add(-2 * time.Minute), true}, // within tolerance
		{start, true},
		{start.Add(3 * time.Hour), true},
		{start.Add(6*time.Hour - time.Minute), true},
		{start.Add(6*time.Hour + 10*time.Minute), false},
		{start.Add(24 * time.Hour), false},
	}
	for _, c := range cases {
		got, err := WindowOpen("0 22 * * 6", "America/Los_Angeles", 6*time.Hour, c.at.UTC(), 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("at %s: got %v want %v", c.at, got, c.want)
		}
	}
	if ok, _ := WindowOpen("", "", time.Hour, time.Now(), 0); !ok {
		t.Fatal("empty cron must be open")
	}
	if _, err := WindowOpen("0 22 * * 6", "Mars/Olympus", time.Hour, time.Now(), 0); err == nil {
		t.Fatal("bad tz accepted")
	}
	next, err := NextStart("0 22 * * 6", "America/Los_Angeles", start.Add(time.Hour))
	if err != nil || !next.Equal(start.Add(7*24*time.Hour)) {
		t.Fatalf("next: %v %v", next, err)
	}
}
