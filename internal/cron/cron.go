// Package cron is a small five-field crontab matcher used for scan windows
// (PLAN §11). It supports *, lists, ranges, steps and month/weekday names;
// when both day-of-month and day-of-week are restricted either may match,
// as in Vixie cron. Resolution is one minute.
package cron

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed expression.
type Schedule struct {
	minute, hour, dom, month, dow [64]bool
	domStar, dowStar              bool
	expr                          string
}

var monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
var dowNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// Parse parses "min hour dom month dow".
func Parse(expr string) (*Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron %q: need 5 fields", expr)
	}
	s := &Schedule{expr: expr}
	var err error
	if s.minute, _, err = parseField(fields[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("cron minute: %w", err)
	}
	if s.hour, _, err = parseField(fields[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("cron hour: %w", err)
	}
	if s.dom, s.domStar, err = parseField(fields[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("cron day-of-month: %w", err)
	}
	if s.month, _, err = parseField(fields[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("cron month: %w", err)
	}
	if s.dow, s.dowStar, err = parseField(fields[4], 0, 7, dowNames); err != nil {
		return nil, fmt.Errorf("cron day-of-week: %w", err)
	}
	if s.dow[7] {
		s.dow[0] = true
	}
	return s, nil
}

func parseField(f string, lo, hi int, names map[string]int) (set [64]bool, star bool, err error) {
	for _, part := range strings.Split(f, ",") {
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			step, err = strconv.Atoi(part[i+1:])
			if err != nil || step < 1 {
				return set, false, fmt.Errorf("bad step in %q", part)
			}
			part = part[:i]
		}
		a, b := lo, hi
		switch {
		case part == "*":
			if step == 1 {
				star = true
			}
		case strings.Contains(part, "-"):
			i := strings.Index(part, "-")
			if a, err = atom(part[:i], names); err != nil {
				return set, false, err
			}
			if b, err = atom(part[i+1:], names); err != nil {
				return set, false, err
			}
		default:
			if a, err = atom(part, names); err != nil {
				return set, false, err
			}
			b = a
			if step > 1 { // "5/10" means 5-hi/10
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return set, false, fmt.Errorf("%q out of range %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			set[v] = true
		}
	}
	return set, star, nil
}

func atom(s string, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("bad value %q", s)
	}
	return v, nil
}

// Matches reports whether the schedule fires in the minute containing t.
func (s *Schedule) Matches(t time.Time) bool {
	if !s.minute[t.Minute()] || !s.hour[t.Hour()] || !s.month[int(t.Month())] {
		return false
	}
	dom := s.dom[t.Day()]
	dow := s.dow[int(t.Weekday())]
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dow
	case s.dowStar:
		return dom
	}
	return dom || dow
}

// Next returns the first firing strictly after t, or an error if none
// occurs within 400 days.
func (s *Schedule) Next(t time.Time) (time.Time, error) {
	c := t.Truncate(time.Minute).Add(time.Minute)
	limit := t.Add(400 * 24 * time.Hour)
	for c.Before(limit) {
		if s.Matches(c) {
			return c, nil
		}
		c = c.Add(time.Minute)
	}
	return time.Time{}, errors.New("cron: no firing within 400 days")
}

// LastStart returns the most recent firing at or before t that is no
// older than dur, i.e. the start of the window t falls in, and whether
// there is one.
func (s *Schedule) LastStart(t time.Time, dur time.Duration) (time.Time, bool) {
	c := t.Truncate(time.Minute)
	earliest := t.Add(-dur)
	for !c.Before(earliest) {
		if s.Matches(c) {
			return c, true
		}
		c = c.Add(-time.Minute)
	}
	return time.Time{}, false
}

// WindowOpen reports whether t (with tolerance either way, for clock skew)
// falls inside a window that started at a cron firing and lasts dur.
func WindowOpen(expr, tz string, dur time.Duration, t time.Time, tolerance time.Duration) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return true, nil
	}
	s, err := Parse(expr)
	if err != nil {
		return false, err
	}
	loc := time.UTC
	if tz != "" {
		if loc, err = time.LoadLocation(tz); err != nil {
			return false, fmt.Errorf("window tz %q: %w", tz, err)
		}
	}
	if dur <= 0 {
		dur = time.Hour
	}
	local := t.In(loc)
	// Open if any firing S satisfies S ≤ t+tol and t-tol < S+dur.
	if start, ok := s.LastStart(local.Add(tolerance), dur+2*tolerance); ok {
		return local.Add(-tolerance).Before(start.Add(dur)), nil
	}
	return false, nil
}

// NextStart returns the next firing after t in the window's timezone.
func NextStart(expr, tz string, t time.Time) (time.Time, error) {
	s, err := Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	loc := time.UTC
	if tz != "" {
		if loc, err = time.LoadLocation(tz); err != nil {
			return time.Time{}, fmt.Errorf("window tz %q: %w", tz, err)
		}
	}
	return s.Next(t.In(loc))
}
