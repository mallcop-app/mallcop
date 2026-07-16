package autonomy

import "testing"

func TestParseKnownValues(t *testing.T) {
	cases := []struct {
		in   string
		want Dial
	}{
		{"non", NonAutonomy},
		{"semi", SemiAutonomy},
		{"fully", FullyAutonomy},
		{" Fully ", FullyAutonomy}, // trimmed/case-insensitive
		{"SEMI", SemiAutonomy},
		{"", NonAutonomy}, // empty -> fail-safe default
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"off", "on", "auto", "full", "nonn"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should be a loud error", bad)
		}
	}
}

func TestNormalizedZeroValueIsNon(t *testing.T) {
	var d Dial // zero value — a caller that never set the field
	if got := d.Normalized(); got != NonAutonomy {
		t.Fatalf("zero-value Dial.Normalized() = %q, want %q", got, NonAutonomy)
	}
}

// TestAutoAppliesData proves ONLY non withholds data auto-apply.
func TestAutoAppliesData(t *testing.T) {
	cases := []struct {
		d    Dial
		want bool
	}{
		{NonAutonomy, false},
		{SemiAutonomy, true},
		{FullyAutonomy, true},
		{"", false}, // zero value normalizes to non
	}
	for _, c := range cases {
		if got := c.d.AutoAppliesData(); got != c.want {
			t.Errorf("Dial(%q).AutoAppliesData() = %v, want %v", c.d, got, c.want)
		}
	}
}

// TestAutonomyVocabularyPinnedAcrossRepoBoundary is a CONTRACT test: this
// package is a mallcop-pro-LOCAL DUPLICATE of mallcop's
// core/config.Learning.Autonomy enum (see this file's package doc) — mallcop-pro
// does not import the mallcop module, so the two vocabularies are two
// independent spellings with NO shared code. See mallcop's
// core/config/config_test.go: TestAutonomyVocabularyPinnedAcrossRepoBoundary
// (same name, other repo). Keep the accepted set literal here (not derived
// from Parse's switch) so a spelling added/removed on ONE side without the
// other is a visible one-line diff a reviewer catches by diffing this literal
// against the mallcop-side literal — not a shared import that would silently
// keep both in sync (and defeat the module-boundary rule this package's doc
// comment exists to enforce).
func TestAutonomyVocabularyPinnedAcrossRepoBoundary(t *testing.T) {
	want := map[string]bool{"non": true, "semi": true, "fully": true}

	got := map[string]bool{string(NonAutonomy): true, string(SemiAutonomy): true, string(FullyAutonomy): true}
	if len(got) != len(want) {
		t.Fatalf("NonAutonomy/SemiAutonomy/FullyAutonomy collapsed to %d distinct values, want 3", len(got))
	}
	for v := range want {
		if !got[v] {
			t.Fatalf("expected dial %q missing from {non=%q, semi=%q, fully=%q}", v, NonAutonomy, SemiAutonomy, FullyAutonomy)
		}
	}

	// Every one-character-off / retired spelling a --autonomy flag value or a
	// mallcop.yaml learning.autonomy string might carry must be REJECTED by
	// Parse — pinning the set to EXACTLY these three, never a superset.
	for _, bad := range []string{"off", "on", "auto", "full", "nonn", "Non!", "non,semi,fully"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("Parse(%q) succeeded, want error (accepted set is EXACTLY {non, semi, fully})", bad)
		}
	}
	for v := range want {
		got, err := Parse(v)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", v, err)
		}
		if string(got) != v {
			t.Fatalf("Parse(%q) = %q, want %q", v, got, v)
		}
	}
}

// TestAutoAppliesCode proves ONLY fully auto-applies code.
func TestAutoAppliesCode(t *testing.T) {
	cases := []struct {
		d    Dial
		want bool
	}{
		{NonAutonomy, false},
		{SemiAutonomy, false},
		{FullyAutonomy, true},
		{"", false},
	}
	for _, c := range cases {
		if got := c.d.AutoAppliesCode(); got != c.want {
			t.Errorf("Dial(%q).AutoAppliesCode() = %v, want %v", c.d, got, c.want)
		}
	}
}
