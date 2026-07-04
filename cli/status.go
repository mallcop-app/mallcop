package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mallcop-app/mallcop/core/store"
)

// runStatus implements `mallcop status`: report the current state of a findings
// store. It opens the git-backed store at --store and reports how many findings
// and resolutions are durably recorded. There is no chart and no separate
// run-state file — the store IS the state.
//
// Terminology: this prints "Decisions: N recorded" — the total count of
// resolution records ever written to the store (every cascade verdict,
// escalate included). That is deliberately a different word from `mallcop
// scan`'s per-run "Resolved: N" summary line, which counts only the
// non-escalate (auto-resolved-by-inference) subset of THIS scan's findings.
// Reusing "Resolved" for both would read as the same measurement when it
// isn't: a store can show "Decisions: 2 recorded" for a scan that itself
// reported "Resolved: 0" (both findings escalated).
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store to report on (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *storePath == "" {
		return fmt.Errorf("status: --store is required (the git-repo path written by `mallcop scan`)")
	}

	fmt.Printf("Store:      %s\n", *storePath)

	if _, err := os.Stat(filepath.Join(*storePath, ".git")); err != nil {
		fmt.Printf("State:      uninitialized (no scan has written here yet)\n")
		return nil
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("status: open store %q: %w", *storePath, err)
	}

	findings, err := st.Load(store.KindFindings)
	if err != nil {
		return fmt.Errorf("status: load findings: %w", err)
	}
	resolutions, err := st.Load(store.KindResolutions)
	if err != nil {
		return fmt.Errorf("status: load resolutions: %w", err)
	}

	fmt.Printf("Findings:   %d recorded\n", len(findings))
	fmt.Printf("Decisions:  %d recorded\n", len(resolutions))
	fmt.Printf("State:      idle\n")
	return nil
}
