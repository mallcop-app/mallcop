// grounding_prompt_test.go — mallcoppro-6a4: the system prompt's Grounding
// section had no rule for a finding with no event linkage, and the model
// silently pivoted to a DIFFERENT finding it could fully resolve instead of
// saying so. These tests pin the presence of the fallback rule (and the
// still-standing never-ask-for-ids guardrail) in the shipped default system
// prompt, so a future edit that drops either guardrail is caught here rather
// than only in a live session postmortem.
package investigate

import (
	"strings"
	"testing"
)

// TestDefaultSystemPrompt_HasNoLinkageFallbackRule proves the mallcoppro-6a4
// fix landed: the prompt explicitly tells the analyst to say so and stay on
// the SAME finding when it lacks event linkage, rather than silently
// switching to a different, fully-resolvable finding.
func TestDefaultSystemPrompt_HasNoLinkageFallbackRule(t *testing.T) {
	prompt := defaultSystemPrompt

	mustContain := []string{
		"NO event linkage",
		"SAY SO PLAINLY",
		"Do NOT silently pivot to a different finding",
	}
	for _, want := range mustContain {
		if !strings.Contains(prompt, want) {
			t.Errorf("default system prompt missing the mallcoppro-6a4 no-linkage fallback rule "+
				"(expected to contain %q)\nprompt:\n%s", want, prompt)
		}
	}
}

// TestDefaultSystemPrompt_StillForbidsAskingForIDs proves the pre-existing
// never-ask-for-ids guardrail (the thing mallcoppro-6a4's fix must NOT
// regress) is still present alongside the new fallback rule.
func TestDefaultSystemPrompt_StillForbidsAskingForIDs(t *testing.T) {
	if !strings.Contains(defaultSystemPrompt, "NEVER ask the operator to supply an id") {
		t.Fatal("default system prompt lost the never-ask-for-ids guardrail")
	}
}

// TestDefaultSystemPrompt_FallbackRuleLivesInGroundingSection proves the new
// rule was added to the "## Grounding on a finding" section (where the
// postmortem traced the gap to), not some unrelated part of the prompt.
func TestDefaultSystemPrompt_FallbackRuleLivesInGroundingSection(t *testing.T) {
	const groundingHeader = "## Grounding on a finding"
	idx := strings.Index(defaultSystemPrompt, groundingHeader)
	if idx < 0 {
		t.Fatal("default system prompt missing the '## Grounding on a finding' section entirely")
	}
	// The next "## " heading after Grounding bounds the section.
	rest := defaultSystemPrompt[idx+len(groundingHeader):]
	nextHeading := strings.Index(rest, "\n## ")
	section := rest
	if nextHeading >= 0 {
		section = rest[:nextHeading]
	}
	if !strings.Contains(section, "NO event linkage") {
		t.Errorf("the no-linkage fallback rule is not inside the '## Grounding on a finding' section:\n%s", section)
	}
}
