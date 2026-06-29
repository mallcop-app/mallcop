// router.go — the DATA-DRIVEN pre-LLM floor.
//
// The operator rejected a hardcoded Go family map for the auto-escalate floor.
// What ships instead is a router that reads its always-escalate routes from the
// SAME mutable corpus the investigate tools consult: agents/rules/operator-
// decisions.yaml, top-level key `escalate_routes`. A finding whose family (and
// optional metadata predicate) matches a route is FORCE-ESCALATED to a human
// before any model call — the model never sees it, no donuts spent.
//
// Why data, not code:
//   - An operator (or a learning loop) extends the floor by appending YAML, with
//     NO Go change and NO redeploy of compiled logic. That is the emergence
//     property the router_test.go EMERGENCE case proves.
//   - The seed below is exactly the proven always-escalate set, so dropping the
//     old hardcoded map does not lower day-one behavior.
//
// This package must reach the model ONLY through the anthropic.Client interface.
// The router does pure disk I/O (read a YAML corpus) and YAML parsing — no
// inference, no network, no transport. The import-lint (imports_test.go) keeps
// it that way.
package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	mallcoplegion "github.com/mallcop-app/mallcop"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// EscalateRoute is a single always-escalate rule loaded from the
// `escalate_routes` section of operator-decisions.yaml. A finding that matches
// a route is force-escalated by the pre-LLM floor.
//
// Family matches finding.Type, hardened against case/whitespace/separator/alias
// evasion (see normalizeFamily). Aliases are alternate or evasion spellings of
// the same dangerous signature; each is normalized before comparison.
// MetadataMatch, when non-empty, is an additional conjunctive predicate over the
// finding's observable metadata (case-insensitive). When empty, the route fires
// on family match alone.
type EscalateRoute struct {
	ID            string            `yaml:"id"`
	Family        string            `yaml:"family"`
	Aliases       []string          `yaml:"aliases,omitempty"`
	MetadataMatch map[string]string `yaml:"metadata_match,omitempty"`
	Reason        string            `yaml:"reason"`
}

// escalateRoutesFile is the on-disk top-level shape this loader reads. It only
// models `escalate_routes`; the `rules:` resolve corpus is owned by the
// core/tools loader and ignored here.
type escalateRoutesFile struct {
	EscalateRoutes []EscalateRoute `yaml:"escalate_routes"`
}

// corpusRelPath is the repo-relative location of the operator decision corpus.
// Same file the core/tools lookup-rules loader reads — one corpus, two readers.
var corpusRelPath = filepath.Join("agents", "rules", "operator-decisions.yaml")

// routesCache memoizes the parsed-and-compiled routes PER corpus path so the
// floor does not re-read and re-parse the YAML on every finding. It is a map
// keyed on the resolved corpus path — NOT a single mutable slot — so two
// concurrent resolves over DIFFERENT corpus paths (e.g. parallel tests, each
// with its own temp corpus) never evict each other's entry. This is part of the
// race-proofing: there is no shared "current key" a concurrent load can stomp,
// so a sibling's resolve can never flip this path's compiled routes mid-read.
var (
	routesCacheMu sync.Mutex
	routesCache   = map[string]routesCacheEntry{}
)

// routesCacheEntry is one path's memoized result: either compiled routes or the
// load error (an unparseable corpus is cached as an error so the fail-safe is
// stable across repeated reads of the same broken file).
type routesCacheEntry struct {
	data *compiledRoutes
	err  error
}

// compiledRoutes is the matcher-ready form of the corpus: the raw routes plus,
// per route, the set of normalized family spellings (canonical family +
// aliases) that trigger it.
type compiledRoutes struct {
	routes []compiledRoute
}

type compiledRoute struct {
	route     EscalateRoute
	canonical string              // normalized canonical family
	triggers  map[string]struct{} // normalized family + all normalized aliases
}

// embedRoutesCacheKey is the sentinel cache key used when routes are compiled
// from the EMBEDDED corpus (no on-disk path). A sentinel rather than a real path
// keeps embed loads memoized without colliding with a real repo-root path or
// with each other across roots.
const embedRoutesCacheKey = ":embed:"

// escalateCorpusBytes resolves the escalate-route corpus bytes with the
// filesystem-first / embed-last precedence (mirrors core/tools.corpusBytes):
//
//  1. When an on-disk root is available (rootErr == nil), read the corpus under
//     repoRoot:
//     - read OK            → DISK bytes (preserves dev edit-and-reload).
//     - os.ErrNotExist     → fall through to the embed (absent, not broken).
//     - any other error    → propagate (never mask a corrupt corpus with the embed).
//  2. Otherwise (the root resolver itself failed — the /tmp standalone-binary
//     case), use the embedded corpus, UNLESS MALLCOP_RULES_EMBED_DISABLE is set
//     (the escape hatch forcing the on-disk-only path).
//
// The returned cacheKey is the on-disk path for disk bytes, or
// embedRoutesCacheKey for the embed.
func escalateCorpusBytes(repoRoot string, rootErr error) (data []byte, cacheKey string, err error) {
	if rootErr == nil {
		path := filepath.Join(repoRoot, corpusRelPath)
		b, rerr := os.ReadFile(path)
		if rerr == nil {
			return b, path, nil
		}
		if !errors.Is(rerr, os.ErrNotExist) {
			return nil, path, fmt.Errorf("read escalate_routes corpus: %w", rerr)
		}
		// Absent on-disk corpus → fall through to the embed.
	}
	if isTruthyEnv(os.Getenv("MALLCOP_RULES_EMBED_DISABLE")) {
		// Escape hatch: on-disk-only. No readable file and embed disabled means
		// an empty floor (the gate's downstream fail-safe still covers the
		// dangerous case).
		return nil, embedRoutesCacheKey + ":disabled", nil
	}
	return mallcoplegion.OperatorDecisionsYAML, embedRoutesCacheKey, nil
}

// isTruthyEnv returns true for common truthy env values, case-insensitive.
func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// loadEscalateRoutes reads and compiles the escalate_routes for the resolved
// root, falling back to the EMBEDDED corpus when no on-disk corpus can be
// located. rootErr carries any failure from the caller's resolveRepoRoot() walk;
// a resolution failure is NO LONGER fatal here — it routes to the embed, which
// always parses, so the standalone /tmp binary loads the baked-in routes instead
// of fail-safe-escalating everything.
//
// A missing corpus (absent path, or embed disabled with no file) yields an EMPTY
// route set (not an error): no data-driven floor, which the caller treats as
// fail-safe (the gate still escalates anything it cannot positively clear). A
// present-but-unparseable corpus (disk OR embed) IS an error, surfaced to the
// caller so a tampered/broken floor fails loud rather than silently disabling
// escalation.
func loadEscalateRoutes(repoRoot string, rootErr error) (*compiledRoutes, error) {
	data, cacheKey, err := escalateCorpusBytes(repoRoot, rootErr)
	if err != nil {
		return nil, err
	}

	routesCacheMu.Lock()
	defer routesCacheMu.Unlock()

	if e, ok := routesCache[cacheKey]; ok {
		return e.data, e.err
	}

	if data == nil {
		// No corpus → empty floor.
		empty := &compiledRoutes{}
		routesCache[cacheKey] = routesCacheEntry{data: empty}
		return empty, nil
	}

	var file escalateRoutesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		parseErr := fmt.Errorf("parse escalate_routes corpus: %w", err)
		routesCache[cacheKey] = routesCacheEntry{err: parseErr}
		return nil, parseErr
	}

	compiled := &compiledRoutes{routes: make([]compiledRoute, 0, len(file.EscalateRoutes))}
	for _, r := range file.EscalateRoutes {
		cr := compiledRoute{
			route:     r,
			canonical: normalizeFamily(r.Family),
			triggers:  map[string]struct{}{},
		}
		// The canonical family always triggers.
		cr.triggers[stripSeparators(strings.ToLower(strings.TrimSpace(r.Family)))] = struct{}{}
		// Every alias, normalized the same way, also triggers.
		for _, a := range r.Aliases {
			cr.triggers[stripSeparators(strings.ToLower(strings.TrimSpace(a)))] = struct{}{}
		}
		compiled.routes = append(compiled.routes, cr)
	}

	routesCache[cacheKey] = routesCacheEntry{data: compiled}
	return compiled, nil
}

// invalidateRoutesCache drops EVERY memoized path. Retained for the
// SetRepoRootForTest seam (a root change there can re-point the floor at a new
// corpus). Prefer invalidateRoutesCacheFor in tests that rewrite a known
// corpus's bytes — it drops only that path, never a sibling's entry.
func invalidateRoutesCache() {
	routesCacheMu.Lock()
	defer routesCacheMu.Unlock()
	routesCache = map[string]routesCacheEntry{}
}

// invalidateRoutesCacheFor drops ONLY the memoized routes for the corpus under
// repoRoot, so a test that rewrites its own temp corpus's bytes forces a re-read
// of just that file (proving a freshly-appended route takes effect with no
// process restart) WITHOUT evicting any concurrent sibling test's entry — part
// of the race-proofing.
func invalidateRoutesCacheFor(repoRoot string) {
	path := filepath.Join(repoRoot, corpusRelPath)
	routesCacheMu.Lock()
	defer routesCacheMu.Unlock()
	delete(routesCache, path)
}

// matchEscalateRoute returns the matching route (and true) when the finding
// trips an always-escalate route, or (zero, false) when it does not. Matching:
//
//  1. The finding's family is normalized (case-folded, whitespace-trimmed,
//     separators stripped) and compared against each route's trigger set
//     (canonical family + aliases, normalized the same way). This is the BYPASS
//     defense: "Injection-Probe", "injection_probe", "  injection-probe  ",
//     and the route's listed aliases all collapse onto the route.
//  2. If a route has a metadata_match predicate, every (key, value) pair must be
//     present (case-insensitively) in the finding's observable metadata for the
//     route to fire. A route with no predicate fires on family match alone.
//
// The first matching route wins (corpus order). Pure function over the compiled
// routes — no I/O.
func matchEscalateRoute(c *compiledRoutes, f finding.Finding) (EscalateRoute, bool) {
	if c == nil {
		return EscalateRoute{}, false
	}
	famKey := stripSeparators(strings.ToLower(strings.TrimSpace(f.Type)))
	if famKey == "" {
		return EscalateRoute{}, false
	}
	meta := findingMetadata(f)
	for _, cr := range c.routes {
		if _, ok := cr.triggers[famKey]; !ok {
			continue
		}
		if !metadataSatisfies(meta, cr.route.MetadataMatch) {
			continue
		}
		return cr.route, true
	}
	return EscalateRoute{}, false
}

// metadataSatisfies reports whether every (key, value) in want is present in
// have (case-insensitive key and value). An empty/absent want is satisfied by
// any metadata (the route fires on family alone).
func metadataSatisfies(have, want map[string]string) bool {
	for k, wv := range want {
		got, ok := lookupCaseInsensitive(have, k)
		if !ok || !strings.EqualFold(got, wv) {
			return false
		}
	}
	return true
}

// lookupCaseInsensitive does a case-insensitive key lookup against m.
func lookupCaseInsensitive(m map[string]string, key string) (string, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	lk := strings.ToLower(key)
	for k, v := range m {
		if strings.ToLower(k) == lk {
			return v, true
		}
	}
	return "", false
}

// findingMetadata projects the observable, predicate-matchable fields of a
// finding into a flat map. The escalate-route predicates match against the
// finding's structural fields (actor, source, severity) — the same observable
// surface the resolve rules match against. Routes that fire on family alone
// (the common dangerous-family case) never consult this.
func findingMetadata(f finding.Finding) map[string]string {
	return map[string]string{
		"actor":    f.Actor,
		"source":   f.Source,
		"severity": f.Severity,
	}
}
