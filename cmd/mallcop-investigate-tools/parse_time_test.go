package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---- parseTimeArg unit tests -----------------------------------------------

func TestParseTimeArg_RFC3339(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseTimeArg("2026-04-10T10:00:00Z", now)
	if err != nil {
		t.Fatalf("parseTimeArg returned error: %v", err)
	}
	want := time.Date(2026, 4, 10, 10, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTimeArg_BareDate(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseTimeArg("2026-04-10", now)
	if err != nil {
		t.Fatalf("parseTimeArg returned error: %v", err)
	}
	want := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTimeArg_NaturalLanguage(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Time
	}{
		{"now", now},
		{"yesterday", now.Add(-24 * time.Hour)},
		{"last week", now.Add(-7 * 24 * time.Hour)},
		{"last month", now.Add(-30 * 24 * time.Hour)},
		{"1 hour ago", now.Add(-1 * time.Hour)},
		{"2 days ago", now.Add(-2 * 24 * time.Hour)},
		{"10 weeks ago", now.Add(-10 * 7 * 24 * time.Hour)},
		{"3 months ago", now.Add(-3 * 30 * 24 * time.Hour)},
		{"1 year ago", now.Add(-365 * 24 * time.Hour)},
		// Case + whitespace tolerance.
		{"  10 WEEKS  AGO  ", now.Add(-10 * 7 * 24 * time.Hour)},
		{"YESTERDAY", now.Add(-24 * time.Hour)},
	}
	for _, tc := range cases {
		got, err := parseTimeArg(tc.in, now)
		if err != nil {
			t.Errorf("parseTimeArg(%q) error: %v", tc.in, err)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("parseTimeArg(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseTimeArg_Malformed(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	cases := []string{
		"",
		"   ",
		"banana",
		"tomorrow morning",
		"10 fortnights ago",
		"recently",
		"-3 days ago",
		"3 days from now",
	}
	for _, in := range cases {
		_, err := parseTimeArg(in, now)
		if err == nil {
			t.Errorf("parseTimeArg(%q) expected error, got nil", in)
		}
	}
}

// ---- search-events --since end-to-end tests --------------------------------

// dynamicEventsJSON builds an events.json relative to `now` so that
// "N weeks ago" filtering is deterministic regardless of wall-clock.
func dynamicEventsJSON(now time.Time) string {
	mk := func(id string, ago time.Duration, actor string) string {
		ts := now.Add(-ago).UTC().Format(time.RFC3339)
		return fmt.Sprintf(`{
			"id": %q,
			"timestamp": %q,
			"source": "github",
			"event_type": "login",
			"actor": %q,
			"action": "user.login",
			"target": "github.com",
			"severity": "info"
		}`, id, ts, actor)
	}
	return `{"events":[` +
		mk("evt-recent", 1*time.Hour, "alice@example.com") + "," +
		mk("evt-3d", 3*24*time.Hour, "alice@example.com") + "," +
		mk("evt-2w", 14*24*time.Hour, "alice@example.com") + "," +
		mk("evt-old", 100*24*time.Hour, "alice@example.com") +
		`]}`
}

// TestSearchEvents_SinceRFC3339_Parses asserts the original RFC3339 path is
// preserved. This is the existing behaviour mallcoppro-cf1 must not regress.
func TestSearchEvents_SinceRFC3339_Parses(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--since", "2026-04-10T00:00:00Z",
			"--until", "2026-04-10T23:59:59Z",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	result := decodeSearchEventsWrapped(t, out)
	if len(result.Events) != 2 {
		t.Fatalf("want 2 events on 2026-04-10, got %d\nout=%q", len(result.Events), out)
	}
}

// TestSearchEvents_SinceNaturalLanguage_Parses asserts the new natural-language
// path. This is the failure observed in the mallcoppro-499 VA-02 scenario:
// the model emitted "10 weeks ago" and the tool crashed with "cannot parse".
func TestSearchEvents_SinceNaturalLanguage_Parses(t *testing.T) {
	now := time.Now().UTC()
	events := dynamicEventsJSON(now)
	dir := makeFixtureDir(t, "", events, "")

	cases := []struct {
		name      string
		since     string
		wantCount int // events newer than `since`
	}{
		// 10 weeks back → includes all but evt-old (100d ago).
		{"10 weeks ago", "10 weeks ago", 3},
		// 2 days back → only evt-recent (1h).
		{"2 days ago", "2 days ago", 1},
		// yesterday → only evt-recent (1h).
		{"yesterday", "yesterday", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				err := run([]string{
					"--tool", "search-events",
					"--mode", "exam",
					"--fixture-dir", dir,
					"--actor", "alice@example.com",
					"--since", tc.since,
				})
				if err != nil {
					t.Fatalf("run() returned error for --since %q: %v", tc.since, err)
				}
			})

			result := decodeSearchEventsWrapped(t, out)
			if len(result.Events) != tc.wantCount {
				t.Errorf("--since %q: got %d events, want %d\nout=%q",
					tc.since, len(result.Events), tc.wantCount, out)
			}
		})
	}
}

// TestSearchEvents_SinceMalformed_Errors asserts gibberish still produces a
// clean error rather than silently matching everything.
func TestSearchEvents_SinceMalformed_Errors(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	cases := []string{
		"banana",
		"tomorrow morning",
		"10 fortnights ago",
		"sometime last quarter",
	}

	for _, since := range cases {
		t.Run(since, func(t *testing.T) {
			err := run([]string{
				"--tool", "search-events",
				"--mode", "exam",
				"--fixture-dir", dir,
				"--actor", "alice@example.com",
				"--since", since,
			})
			if err == nil {
				t.Fatalf("expected error for malformed --since %q, got nil", since)
			}
			if !strings.Contains(err.Error(), "parse --since") {
				t.Errorf("error should mention 'parse --since', got: %v", err)
			}
		})
	}
}

// TestSearchFindings_SinceNaturalLanguage_Parses asserts the same parser also
// covers the --since arg on search-findings (same crash surface).
func TestSearchFindings_SinceNaturalLanguage_Parses(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	old := now.Add(-100 * 24 * time.Hour).Format(time.RFC3339)

	findings := fmt.Sprintf(
		`{"id":"fnd-recent","actor":"alice@example.com","source":"github","timestamp":%q,"title":"recent"}
{"id":"fnd-old","actor":"alice@example.com","source":"github","timestamp":%q,"title":"old"}
`, recent, old)

	dir := makeFixtureDir(t, "", "", findings)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--since", "2 days ago",
		})
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 finding in last 2 days, got %d\nout=%q", len(lines), out)
	}
	if !strings.Contains(lines[0], "fnd-recent") {
		t.Errorf("expected fnd-recent in output, got: %s", lines[0])
	}
}
