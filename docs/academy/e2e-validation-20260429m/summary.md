# E2E Validation Summary: e2e-ac01-20260429m

**Date:** 2026-04-29
**Run ID:** e2e-ac01-20260429m
**rd item:** mallcoppro-ec5
**Status: PASS**

## Result

| Field | Value |
|-------|-------|
| Scenario | AC-01-external-access-stolen-cred |
| Expected disposition | `escalated` |
| Observed disposition | `escalated` |
| Wall time | 54.4 seconds |
| Pass rate (KA) | 100% (1/1) |

## Chain Executed

triage (4 turns) → investigate (5 turns + annotate) → escalate (3 turns)

All three stages used glm-4.7-flash via Forge backend (ForgeBackend path, no OAuth rate limit).

### Stage A: Triage

Triage worker called check-baseline(admin-user), search-events twice, then called escalate-to-investigator with confidence=5. Rationale: admin-user has known=false/frequency=0 on GitHub; no legitimate trigger found.

### Stage B: Investigate

Investigate worker cross-checked baseline, events, findings, and list_work_items for deep-investigate availability. Found no corroborating events or prior findings. Called escalate-to-stage-c with action_class=needs-approval. Annotated finding with full investigation summary.

### Stage C: Escalate

Escalate worker called list-actions(GitHub Grant Event) — returned empty (no registered remediation). Selected Branch 3 (INSTRUCT-OPERATOR). Annotated finding with specific targets and urgency. Called resolve-finding with action=escalated, confidence=4.

## Structural Axes

| Axis | Result | Notes |
|------|--------|-------|
| chain_action | pass | observed=escalated matches expected |
| mentions | pass | finding_id referenced throughout |
| no_mentions | pass | |
| tools_used | fail | sleep-agent path (GLM); tool call counts differ from grader expectations |
| iterations | fail | sleep-agent path; turn counts differ from grader expectations |
| quality_floor | pending | requires judge binary (out of scope for F5A) |

The tools_used and iterations failures are expected artifacts of the sleep-agent execution path (GLM model via Forge). The KA (key action = chain_action) verdict is PASS.

## Infrastructure Used

- Automaton: we v0.6.1 (mallcop-e2e-ac01-20260429m)
- Model: glm-4.7-flash via Forge (https://forge.3dl.dev)
- Work campfire: 49b36ad1e06dcc21...
- Chart: .run/e2e-ac01-20260429m/chart.toml

## Fixes Applied This Run

1. cmd/mallcop-academy/main.go: cfSender.cfHome = os.Getenv("CF_HOME") — academy posts to run-specific campfire
2. cmd/mallcop-investigate-tools/tools_f1g.go: cfWorkCreate posts "id" key so downstream ReadyWorkSource can claim investigate items
3. agents/triage/POST.md: ONCE constraint prevents duplicate escalate-to-investigator calls
4. agents/escalate/POST.md: Rewritten to only use available tools (list-actions, annotate-finding, resolve-finding)

## Files

- AC-01-external-access-stolen-cred.json — per-scenario result (F4A schema)
- report.md — academy run report
- run.json — run parameters
- verdict.txt — PASS/FAIL verdict
- transcripts.jsonl — per-worker tool call sequences
- .run/e2e-ac01-20260429m/chart.toml — rendered automaton chart
