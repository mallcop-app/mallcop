package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// runFeedback implements `mallcop feedback <finding_id> approve|dismiss`.
//
// This is the OPERATOR FEEDBACK seam: an operator who has seen a finding (in the
// scan output, or in a Discord post) records a decision that the NEXT scan
// honors. The decision is persisted as a Directive on the store's directives
// stream; pipeline.Run replays that stream and drops suppressed findings.
//
// Both verbs persist a 'suppress' directive (the operator is telling mallcop
// "stop flagging this"), but they record the verb distinctly for the audit
// trail:
//
//	dismiss — operator says the finding is noise / not actionable.
//	approve — operator says the underlying activity is known-good / sanctioned.
//
// The suppress Pattern is derived from the finding's stable key
// "<source>/<type>/<actor>" so the directive suppresses the CLASS of finding,
// not just one transient per-run finding ID (which is not stable across scans).
//
// Usage:
//
//	mallcop feedback <finding_id> approve|dismiss --store <dir> [--reason "..."] [--by <operator>]
func runFeedback(args []string) error {
	// The two positional args (finding_id, action) come FIRST, before any flags,
	// so the operator writes `mallcop feedback <id> dismiss --store <dir>`. Go's
	// flag package stops at the first non-flag token, so we peel the positionals
	// off the front ourselves and parse the remainder as flags.
	if len(args) < 2 {
		return fmt.Errorf("feedback: usage: mallcop feedback <finding_id> approve|dismiss --store <dir> [--reason \"...\"] [--by <operator>]")
	}
	findingID := args[0]
	verb := args[1]

	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by 'mallcop scan' (required)")
	reason := fs.String("reason", "", "Operator rationale for this decision (free text, recorded for audit)")
	by := fs.String("by", "", "Operator identity (defaults to $USER)")

	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	switch verb {
	case "approve", "dismiss":
	default:
		return fmt.Errorf("feedback: unknown action %q (want approve|dismiss)", verb)
	}

	if *storePath == "" {
		return fmt.Errorf("feedback: --store is required (the git-repo path written by 'mallcop scan')")
	}

	operator := *by
	if operator == "" {
		operator = os.Getenv("USER")
	}
	if operator == "" {
		operator = "operator"
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("feedback: open store %q: %w", *storePath, err)
	}

	// Resolve the finding by ID from the durable findings stream.
	f, err := findFindingByID(st, findingID)
	if err != nil {
		return err
	}

	// Derive the stable suppress Pattern from the finding's source/type/actor.
	pattern := f.Source + "/" + f.Type + "/" + f.Actor

	// Record the verb + rationale distinctly in Meta for the audit trail, while
	// the always-works mechanism is the persisted suppress directive.
	meta, err := json.Marshal(map[string]string{
		"verb":       verb,
		"finding_id": f.ID,
		"recorded":   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("feedback: encode meta: %w", err)
	}

	reasonText := *reason
	if reasonText == "" {
		if verb == "approve" {
			reasonText = "operator approved: activity known-good"
		} else {
			reasonText = "operator dismissed: finding not actionable"
		}
	}

	d := store.Directive{
		Op:      "suppress",
		Pattern: pattern,
		Reason:  reasonText,
		Actor:   operator,
		Meta:    json.RawMessage(meta),
	}

	if _, err := st.Append(store.KindDirectives, d); err != nil {
		return fmt.Errorf("feedback: append directive: %w", err)
	}

	fmt.Printf("Recorded %s for finding %s\n", verb, f.ID)
	fmt.Printf("  Suppress pattern: %s\n", pattern)
	fmt.Printf("  Operator:         %s\n", operator)
	fmt.Printf("  Reason:           %s\n", reasonText)
	fmt.Printf("The next scan will suppress findings matching this pattern.\n")
	return nil
}

// findFindingByID replays the findings stream and returns the finding with the
// given ID. It returns a clear error if no finding matches — a bad finding-id
// must fail cleanly, not silently no-op.
func findFindingByID(st *store.Store, id string) (finding.Finding, error) {
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("feedback: load findings: %w", err)
	}
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			// A malformed stored finding is a corruption, surface it.
			return finding.Finding{}, fmt.Errorf("feedback: decode stored finding: %w", err)
		}
		if f.ID == id {
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("feedback: finding %q not found in store (run 'mallcop status --store ...' to list)", id)
}
