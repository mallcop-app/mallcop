// parse_time.go — lenient time parsing for --since / --until.
//
// The triage and investigate dispositions naturally emit relative time
// expressions like "10 weeks ago" when reasoning about event windows.
// search-events previously only accepted RFC3339, so the model would crash
// the tool with parse errors (see mallcoppro-499 VA-02 finding,
// mallcoppro-cf1). parseTimeArg accepts both RFC3339 and a small set of
// natural-language forms, returning a time.Time anchored at nowFn().
//
// Recognized natural-language forms (case-insensitive, whitespace tolerant):
//
//	"<N> seconds ago"
//	"<N> minutes ago"
//	"<N> hours ago"
//	"<N> days ago"
//	"<N> weeks ago"
//	"<N> months ago"     (approximate: 30 days)
//	"<N> years ago"      (approximate: 365 days)
//	"yesterday"          (24h ago)
//	"last week"          (7d ago)
//	"last month"         (30d ago)
//	"now"
//
// Anything else returns an error. This is intentionally narrow — we want
// predictable behaviour for an LLM-driven tool, not a full English date
// parser.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseTimeArg parses s as either RFC3339 or a small natural-language form.
// now is the reference time for relative expressions; pass time.Now in
// production. Returns the resolved absolute time, or an error if s matches
// neither shape.
func parseTimeArg(s string, now time.Time) (time.Time, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return time.Time{}, fmt.Errorf("empty time argument")
	}

	// 1. RFC3339 — preserve existing behaviour exactly. If it parses, return.
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return t, nil
	}
	// 2. Also accept the second-precision form used in fixture events.
	if t, err := time.Parse("2006-01-02T15:04:05Z", trimmed); err == nil {
		return t, nil
	}
	// 3. And a plain YYYY-MM-DD date.
	if t, err := time.Parse("2006-01-02", trimmed); err == nil {
		return t, nil
	}

	// 4. Natural-language fallback. Normalize: lowercase + collapse internal
	// whitespace.
	lower := strings.ToLower(trimmed)
	lower = strings.Join(strings.Fields(lower), " ")

	switch lower {
	case "now":
		return now, nil
	case "yesterday":
		return now.Add(-24 * time.Hour), nil
	case "last week":
		return now.Add(-7 * 24 * time.Hour), nil
	case "last month":
		return now.Add(-30 * 24 * time.Hour), nil
	}

	// 5. "<N> <unit> ago" form.
	if strings.HasSuffix(lower, " ago") {
		body := strings.TrimSuffix(lower, " ago")
		parts := strings.Fields(body)
		if len(parts) == 2 {
			n, err := strconv.Atoi(parts[0])
			if err == nil && n >= 0 {
				if d, ok := unitToDuration(parts[1]); ok {
					return now.Add(-time.Duration(n) * d), nil
				}
			}
		}
	}

	return time.Time{}, fmt.Errorf("cannot parse %q as RFC3339 or natural-language time (try \"2026-04-01T00:00:00Z\" or \"10 weeks ago\")", s)
}

// unitToDuration maps a singular or plural English time unit to its duration.
// Month and year are approximate (30d, 365d) — search windows are coarse and
// the LLM-facing UX gains more from accepting "3 months ago" than from
// calendar accuracy.
func unitToDuration(unit string) (time.Duration, bool) {
	switch unit {
	case "second", "seconds", "sec", "secs":
		return time.Second, true
	case "minute", "minutes", "min", "mins":
		return time.Minute, true
	case "hour", "hours", "hr", "hrs":
		return time.Hour, true
	case "day", "days":
		return 24 * time.Hour, true
	case "week", "weeks":
		return 7 * 24 * time.Hour, true
	case "month", "months":
		return 30 * 24 * time.Hour, true
	case "year", "years":
		return 365 * 24 * time.Hour, true
	}
	return 0, false
}
