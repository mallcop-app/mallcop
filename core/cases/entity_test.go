package cases

import "testing"

func TestExtractEntity_GranteeThenTargetThenMemberFallback(t *testing.T) {
	cases := []struct {
		name     string
		evidence string
		want     string
	}{
		{"grantee wins", `{"grantee":"alice","target":"repo-x","member":"arn:aws:iam::1:role/y"}`, "alice"},
		{"target when no grantee", `{"target":"repo-x","member":"arn:aws:iam::1:role/y"}`, "repo-x"},
		{"member when only member", `{"member":"arn:aws:iam::1:role/y"}`, "arn:aws:iam::1:role/y"},
		{"grantee empty string skipped", `{"grantee":"","target":"repo-x"}`, "repo-x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractEntity([]byte(tc.evidence))
			if got != tc.want {
				t.Errorf("ExtractEntity(%s) = %q, want %q", tc.evidence, got, tc.want)
			}
		})
	}
}

func TestExtractEntity_EmptyOnNoMatch(t *testing.T) {
	cases := []struct {
		name     string
		evidence string
	}{
		{"no matching key", `{"actor":"dev","rule":"force-push"}`},
		{"empty evidence", ``},
		{"malformed json", `not json`},
		{"nil evidence", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractEntity([]byte(tc.evidence))
			if got != "" {
				t.Errorf("ExtractEntity(%s) = %q, want empty", tc.evidence, got)
			}
		})
	}
}
