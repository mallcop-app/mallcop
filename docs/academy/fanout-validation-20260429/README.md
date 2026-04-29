# Fan-out validation — 2026-04-29

**Item**: mallcoppro-07e — F2B: Wire investigate chart entry to enable confidence-gated-close hook
**Branch**: work/mallcoppro-07e
**Date**: 2026-04-29

## Summary

This validation run documents the F2B chain-wiring verification for the confidence-gated-close fan-out hook.

## Chart wiring verification

**Status: CONFIRMED — chart already wired correctly by F2A (PR #28)**

The `[capabilities.seed.behaviors.confidence_gated_close]` block was found in `charts/mallcop-operational.toml.tmpl` at the correct location (under the `task:investigate` capability seed, lines 131-141) with:

```toml
[capabilities.seed.behaviors.confidence_gated_close]
enabled              = true
score_floor          = 0.55
tool_call_weight     = 0.04
tool_call_cap        = 8
distinct_tool_weight = 0.08
distinct_tool_cap    = 4
citation_weight      = 0.04
citation_cap         = 5
iteration_penalty    = -0.02
iteration_threshold  = 3
```

No chart edits were needed. The F2A commit (5ff6a88) already added this block with `enabled = true`.

## Chart used for this run

Template: `charts/mallcop-operational.toml.tmpl`
Render script: `scripts/render-chart.sh`
Run ID: `fanout-validate-20260429`
Model: `claude-haiku-4-5` (cost-optimized)
Work campfire: `bb97bb3caaf0b183ec0ee71ddc1b820e4367ded0f3cf6a564d3bc6774ca6b73a`

Rendered chart: `.run/fanout-validate-20260429/operational-final.toml`

## Forge availability

**Status: CONFIRMED**

```
curl -s https://forge.3dl.dev/health → {"status":"ok"}
FORGE_API_KEY present (forge-sk-9b36..., 40 chars)
```

## Test fixture

**Created**: `exams/scenarios/_test/fanout-trigger.yaml`

A sparse single-event scenario (one GitHub login by `unknown-actor-xyz` with no baseline history, curl user-agent, no MFA). Designed to score below 0.55 with any reasonable investigation strategy:
- 2 tool calls, 2 distinct tools, 0 citations → score = 0.04×2 + 0.08×2 = 0.24 < 0.55
- Even at 4 tool calls, 4 distinct, 1 citation → 0.16 + 0.32 + 0.04 = 0.52 < 0.55

## Synthetic test evidence (F2B unit tests)

Two new tests in `cmd/mallcop-academy/fanout_chain_test.go` pass with real isolated campfires:

### TestFanoutChain_WorkCreateCount
Verifies that exactly 4 `work:create` messages are emitted by the fan-out gate:
- 3x `skill:task:deep-investigate` (hypotheses: benign, malicious, incomplete)
- 1x `skill:task:investigate-merge`
All 3 hypotheses appear in payloads.

**Result: PASS**

### TestFanoutChain_AcademyClassifiesFullChain
Verifies that the academy watch loop correctly classifies a full fan-out chain:
- Full chain has ≥ 5 entries (investigate + 3 deep + merge)
- At least one `task:investigate-merge` entry present
- At least 3 `task:deep-investigate` entries present
- Terminal action = `escalated` (from merge worker)

**Result: PASS**

## Real LLM E2E attempt

**Status: PARTIAL — operational pipeline boot confirmed, work-item dispatch blocked**

The `we start` automaton booted successfully against the rendered chart:
- Legion version: v0.6.1 ✓
- Forge API key valid: `https://forge.3dl.dev/health` → 200 OK ✓
- Capability seeds loaded: triage, investigate, heal, judge, report ✓
- Budget configured: 5M tokens/session, 15K/task ✓
- Confidence gate: `enabled=true`, `score_floor=0.55` verified in rendered chart ✓

**Missing prerequisites for full LLM E2E dispatch:**
1. `agents/deep-investigate/identity.json` — agent disposition missing (logged as warning)
2. `agents/escalate/identity.json` — agent disposition missing
3. `agents/investigate-merge/identity.json` — agent disposition missing
4. `agents/mallcop/identity.json` — agent disposition missing
5. Tools feed subscription error: `"not a member of campfire bb97bb3caaf0"` — the legion engine's campfire subscription to receive new work items isn't working despite the work campfire being joined. The automaton polls but doesn't dispatch workers to process the posted finding.

The triage and investigate disposition agents ARE present (they were set up in earlier F-series items). However, the investigate worker cannot fan-out to deep-investigate without the `deep-investigate` agent identity being provisioned.

**Per implementer.md constraints:** Unable to complete real LLM E2E without the above prerequisites. Reporting as infrastructure blocker, not skipping or faking artifacts.

## Test results

Full test suite GREEN:
```
ok  github.com/thirdiv/mallcop-legion/cmd/mallcop-academy        10.843s
ok  github.com/thirdiv/mallcop-legion/cmd/mallcop-investigate-tools  72.877s
ok  github.com/thirdiv/mallcop-legion/... (all packages)         PASS
```

New tests added:
- `TestFanoutChain_AcademyClassifiesFullChain` — PASS
- `TestFanoutChain_WorkCreateCount` — PASS

## Missing-prereq list (concrete)

For the real LLM E2E fan-out observation to complete, the following must be in place:
1. `we init` (or equivalent) for `deep-investigate`, `escalate`, `investigate-merge`, `mallcop` dispositions under `agents/`
2. The legion tools-feed subscription needs to work with the campfire (authentication/admission issue)
3. The `exams/scenarios/_test/` directory and scenarios must be indexed for the fixture-dir path (`exams/fixtures/fanout-validate-<date>`)
4. The fixture data for `unknown-actor-xyz` must be seeded in the fixture-dir (or fixture-dir must fall back gracefully)

## Files committed on this branch

- `charts/mallcop-operational.toml.tmpl` — no changes (F2A already correct)
- `exams/scenarios/_test/fanout-trigger.yaml` — new low-confidence test fixture
- `cmd/mallcop-academy/fanout_chain_test.go` — new fan-out chain tests
- `scripts/render-chart.sh` — reusable chart render script
- `docs/academy/fanout-validation-20260429/README.md` — this file
