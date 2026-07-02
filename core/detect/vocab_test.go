package detect

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// mustJSON marshals v to a json.RawMessage, panicking on error. Used to build
// event payloads in table literals (where no *testing.T is in scope). Test-only.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("mustJSON: " + err.Error())
	}
	return b
}

// collectGateVocabFromSource re-derives the event-type vocabulary DIRECTLY from
// the detector source, independently of vocab.go, via a mechanical go/ast scan
// of every non-test core/detect/*.go file:
//
//	(A) every string literal compared against a `*.Type` selector — ev.Type=="x"
//	    or ev.Type!="x" (BinaryExpr) and `case "x":` under `switch ev.Type`
//	    (SwitchStmt with a `.Type` tag);
//	(B) the keys of every package-level `var …EventTypes = map[…]…{…}` gate map,
//	    plus the `evType:` field of every element of the `configRules` slice
//	    literal (config-drift's per-type rule table).
//
// The union is the ground-truth gate vocabulary the detectors actually enforce.
// TestKnownEventTypesMatchesGates asserts it EQUALS KnownEventTypes() in both
// directions, so the vocabulary cannot silently drift from the real gates.
func collectGateVocabFromSource(t *testing.T) map[string]bool {
	t.Helper()
	vocab := map[string]bool{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++

		// (A) inline ev.Type comparisons and switch-on-.Type cases.
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op != token.EQL && x.Op != token.NEQ {
					return true
				}
				if isTypeSelector(x.X) {
					if lit, ok := stringLit(x.Y); ok {
						vocab[lit] = true
					}
				}
				if isTypeSelector(x.Y) {
					if lit, ok := stringLit(x.X); ok {
						vocab[lit] = true
					}
				}
			case *ast.SwitchStmt:
				if !isTypeSelector(x.Tag) {
					return true
				}
				for _, stmt := range x.Body.List {
					cc, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, expr := range cc.List {
						if lit, ok := stringLit(expr); ok {
							vocab[lit] = true
						}
					}
				}
			}
			return true
		})

		// (B) gate-map keys + configRules[].evType.
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, vname := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					cl, ok := vs.Values[i].(*ast.CompositeLit)
					if !ok {
						continue
					}
					switch {
					case strings.HasSuffix(vname.Name, "EventTypes"):
						// map[string]bool gate set — collect its keys.
						for _, elt := range cl.Elts {
							kv, ok := elt.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if lit, ok := stringLit(kv.Key); ok {
								vocab[lit] = true
							}
						}
					case vname.Name == "configRules":
						// []configDriftRule — collect each element's evType field.
						for _, elt := range cl.Elts {
							ecl, ok := elt.(*ast.CompositeLit)
							if !ok {
								continue
							}
							for _, field := range ecl.Elts {
								kv, ok := field.(*ast.KeyValueExpr)
								if !ok {
									continue
								}
								key, ok := kv.Key.(*ast.Ident)
								if !ok || key.Name != "evType" {
									continue
								}
								if lit, ok := stringLit(kv.Value); ok {
									vocab[lit] = true
								}
							}
						}
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("AST scan covered 0 source files; package layout changed?")
	}
	return vocab
}

// isTypeSelector reports whether e is a selector ending in `.Type` (ev.Type).
func isTypeSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "Type"
}

// stringLit returns the unquoted value of e when it is a string literal.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// TestKnownEventTypesMatchesGates is the membership<->gate coupling proof
// (invariant 11). KnownEventTypes() must equal the vocabulary mechanically
// scanned from the detector source, in BOTH directions:
//   - no DEAD vocab: every KnownEventTypes member is a real gate literal;
//   - no MISSING vocab: every gate literal is a KnownEventTypes member.
//
// A detector that adds a new gate (map key or inline literal) without updating
// the vocabulary, or a vocabulary member with no backing gate, fails this test.
func TestKnownEventTypesMatchesGates(t *testing.T) {
	fromSource := collectGateVocabFromSource(t)
	fromCode := KnownEventTypes()

	if len(fromSource) == 0 {
		t.Fatal("AST scan found no gate literals; the scan is broken (it must find the detector gates)")
	}

	for et := range fromCode {
		if !fromSource[et] {
			t.Errorf("DEAD vocab: KnownEventTypes has %q but no detector gates on it (AST scan found no matching gate)", et)
		}
	}
	for et := range fromSource {
		if !fromCode[et] {
			t.Errorf("MISSING vocab: a detector gates on %q but KnownEventTypes omits it", et)
		}
	}
}

// TestKnownEventTypesFreshCopy proves each call returns an independent map, so a
// caller mutating the result cannot corrupt a later caller's view.
func TestKnownEventTypesFreshCopy(t *testing.T) {
	a := KnownEventTypes()
	a["__sentinel__"] = true
	b := KnownEventTypes()
	if b["__sentinel__"] {
		t.Fatal("KnownEventTypes returned a shared map: a mutation leaked across calls")
	}
}

// TestIsKnownEventTypeNormalizes checks the loader membership helper: a real
// member matches case-insensitively with surrounding whitespace, and a bogus
// type does not.
func TestIsKnownEventTypeNormalizes(t *testing.T) {
	for _, ok := range []string{"login", "  Login ", "AUDIT_LOG_DISABLED", "repo.add_collaborator"} {
		if !IsKnownEventType(ok) {
			t.Errorf("IsKnownEventType(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "not_a_real_type", "github_other", "decl:whatever"} {
		if IsKnownEventType(bad) {
			t.Errorf("IsKnownEventType(%q) = true, want false", bad)
		}
	}
}

// TestKnownEventTypesReflectRealBehavior is the lighter spot-check: for a
// representative sample of members spanning map-based and inline gates, build an
// event with a maximally-triggering payload and assert detect.Detect admits it
// past the owning gate (a finding of the owning detector's Type comes back). It
// proves the vocabulary reflects real detector behavior, not just source text.
func TestKnownEventTypesReflectRealBehavior(t *testing.T) {
	known := KnownEventTypes()

	cases := []struct {
		name       string
		ev         event.Event
		wantFinding string // finding.Type the owning detector emits
	}{
		{
			name: "role_assignment fires priv-escalation",
			ev: event.Event{
				ID: "e1", Source: "azure", Type: "role_assignment", Actor: "mallory",
				Payload: mustJSON(map[string]any{"role": "admin", "target_user": "victim"}),
			},
			wantFinding: "priv-escalation",
		},
		{
			name: "login fires unusual-login",
			ev: event.Event{
				ID: "e2", Source: "okta", Type: "login", Actor: "ghost",
				Payload: mustJSON(map[string]any{"ip": "8.8.8.8"}),
			},
			wantFinding: "unusual-login",
		},
		{
			name: "audit_log_disabled fires config-drift",
			ev: event.Event{
				ID: "e3", Source: "aws", Type: "audit_log_disabled", Actor: "root",
				Payload: mustJSON(map[string]any{}),
			},
			wantFinding: "config-drift",
		},
		{
			name: "push (forced) fires git-oops",
			ev: event.Event{
				ID: "e4", Source: "github", Type: "push", Actor: "dev",
				Payload: mustJSON(map[string]any{"forced": true, "ref": "refs/heads/main"}),
			},
			wantFinding: "git-oops",
		},
		{
			name: "api_request (burst) fires rate-anomaly",
			ev: event.Event{
				ID: "e5", Source: "api", Type: "api_request", Actor: "bot",
				Payload: mustJSON(map[string]any{"request_count": 5000, "endpoint": "/admin/"}),
			},
			wantFinding: "rate-anomaly",
		},
		{
			name: "skill_install (suspicious url) fires malicious-skill",
			ev: event.Event{
				ID: "e6", Source: "marketplace", Type: "skill_install", Actor: "installer",
				Payload: mustJSON(map[string]any{"name": "helper", "url": "https://x.ngrok.io/c2"}),
			},
			wantFinding: "malicious-skill",
		},
		{
			name: "download (large) fires exfil-pattern",
			ev: event.Event{
				ID: "e7", Source: "drive", Type: "download", Actor: "leaker",
				Payload: mustJSON(map[string]any{"bytes_transferred": 900 * 1024 * 1024}),
			},
			wantFinding: "exfil-pattern",
		},
		{
			name: "log_format_drift fires log-format-drift",
			ev: event.Event{
				ID: "e8", Source: "svc", Type: "log_format_drift", Actor: "parser",
				Payload: mustJSON(map[string]any{"metadata": map[string]any{"unmatched_percent": 40}}),
			},
			wantFinding: "log-format-drift",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !known[tc.ev.Type] {
				t.Fatalf("precondition: %q is not a KnownEventTypes member", tc.ev.Type)
			}
			findings := Detect([]event.Event{tc.ev}, &baseline.Baseline{})
			var saw bool
			for _, f := range findings {
				if f.Type == tc.wantFinding {
					saw = true
				}
			}
			if !saw {
				t.Fatalf("event Type %q produced no %q finding; the gate is not reached (findings: %d)",
					tc.ev.Type, tc.wantFinding, len(findings))
			}
		})
	}
}
