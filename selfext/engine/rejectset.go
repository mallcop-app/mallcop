package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// rejectSetFile is the anti-thrash ledger filename, co-located with the
// spendcap state under MALLCOP_SPEND_DIR so it survives across runs.
const rejectSetFile = "selfext-rejects.json"

// envSpendDir mirrors spendcap's MALLCOP_SPEND_DIR — the reject set lives in the
// same directory as the spend ledger.
const envSpendDir = "MALLCOP_SPEND_DIR"

// RejectSet is the persisted set of gap fingerprints the gate has already
// rejected. Consulting it FIRST means the loop never re-spends inference
// re-deriving a known dead end. Safe for concurrent use within one process; the
// JSON file is the cross-run record.
type RejectSet struct {
	mu   sync.Mutex
	path string
	set  map[string]struct{}
}

// rejectFile is the on-disk shape: a sorted list of fingerprints.
type rejectFile struct {
	Fingerprints []string `json:"fingerprints"`
}

// resolveSpendDir resolves the state directory the same way spendcap.New does:
// explicit dir → $MALLCOP_SPEND_DIR → ~/.cache/mallcop.
func resolveSpendDir(dir string) (string, error) {
	if dir == "" {
		dir = os.Getenv(envSpendDir)
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("selfext: resolve home dir: %w", err)
		}
		dir = filepath.Join(home, ".cache", "mallcop")
	}
	return dir, nil
}

// LoadRejectSet loads (or initializes) the reject set from dir. An empty dir
// resolves via $MALLCOP_SPEND_DIR then ~/.cache/mallcop. A missing file is an
// empty set, not an error.
func LoadRejectSet(dir string) (*RejectSet, error) {
	resolved, err := resolveSpendDir(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(resolved, rejectSetFile)
	rs := &RejectSet{path: path, set: map[string]struct{}{}}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rs, nil
		}
		return nil, fmt.Errorf("selfext: read reject set %q: %w", path, err)
	}
	var rf rejectFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("selfext: parse reject set %q: %w", path, err)
	}
	for _, fp := range rf.Fingerprints {
		rs.set[fp] = struct{}{}
	}
	return rs, nil
}

// Has reports whether fp is a known reject.
func (rs *RejectSet) Has(fp string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	_, ok := rs.set[fp]
	return ok
}

// Add records fp as a known reject and persists the set. It is idempotent.
func (rs *RejectSet) Add(fp string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, ok := rs.set[fp]; ok {
		return nil
	}
	rs.set[fp] = struct{}{}
	return rs.persistLocked()
}

// Len returns the number of known rejects.
func (rs *RejectSet) Len() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.set)
}

// persistLocked writes the set to its JSON file. Caller must hold rs.mu.
func (rs *RejectSet) persistLocked() error {
	fps := make([]string, 0, len(rs.set))
	for fp := range rs.set {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	if err := os.MkdirAll(filepath.Dir(rs.path), 0o755); err != nil {
		return fmt.Errorf("selfext: create reject-set dir: %w", err)
	}
	data, err := json.MarshalIndent(rejectFile{Fingerprints: fps}, "", "  ")
	if err != nil {
		return fmt.Errorf("selfext: marshal reject set: %w", err)
	}
	if err := os.WriteFile(rs.path, data, 0o644); err != nil {
		return fmt.Errorf("selfext: write reject set %q: %w", rs.path, err)
	}
	return nil
}
