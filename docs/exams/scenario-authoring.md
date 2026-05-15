# Scenario Authoring Guide

This guide defines the hard-constraint contract that every scenario author must
follow. Violating it produces deterministically failing scenarios that waste eval
budget.

## Hard-Constraint Detectors

The academy implements a **rung-0 short-circuit** for a fixed set of detector
classes. When a scenario's `finding.detector` matches one of these values, the
academy bypasses the LLM pipeline entirely and records a synthetic
`action: escalated` terminal without spawning any model worker.

**Authoritative source:** `cmd/mallcop-academy/hard_constraints.go`
(`alwaysEscalateDetectors` map).

| Detector | Why it always escalates |
|---|---|
| `priv-escalation` | Privilege changes always require human audit |
| `log-format-drift` | Structural drift creates security blind spots |
| `injection-probe` | Prompt-injection attempts are deterministic escalations |
| `boundary-violation` | Access-boundary violations always require human review |

### The contract

Scenarios whose `finding.detector` matches any key in `alwaysEscalateDetectors`
**MUST** set:

```yaml
expected:
  chain_action: escalated
```

Setting `expected.chain_action: resolved` (or any value other than `escalated`)
for these detectors is **unreachable** — the academy short-circuits to a
synthetic terminal before any model is consulted. The scenario will
deterministically fail evaluation every time.

### Why this exists

The rung-0 ladder was introduced to avoid spending donuts on scenarios the
system would always escalate by policy. See `docs/diagnosis/2026-05-05-ladder-gap.md`
(in mallcop-pro) for the cost projection and full rationale.

### Checking if your detector is in the always-escalate set

```bash
grep -A10 'alwaysEscalateDetectors' cmd/mallcop-academy/hard_constraints.go
```

### What happens at runtime

1. The seed step checks `checkHardConstraints(finding.Detector)`.
2. If matched: a synthetic `work:close` event with `action: escalated` is posted
   to the work campfire. No `work:create` is posted. No triage skill runs. No
   model worker is spawned.
3. The scenario is recorded as terminal with `terminalAction: escalated`.
4. Evaluation grading compares this against `expected.chain_action`. A mismatch
   (e.g., `resolved`) is a deterministic failure.

## Scenario YAML quick reference

See `exams/scenarios/_schema.yaml` for the full field list.

Key fields for hard-constraint scenarios:

```yaml
id: PE-XX-my-scenario
detector: priv-escalation   # always-escalate detector — must set chain_action: escalated
finding:
  detector: priv-escalation
expected:
  chain_action: escalated   # REQUIRED for hard-constraint detectors
  triage_action: escalated  # consistent with chain_action
```

## Adding new always-escalate detectors

**Do NOT add detectors to `alwaysEscalateDetectors` without a design decision.**
The rung-0 set is a small, deterministic, security-critical allowlist. New
detectors must go through the LLM triage path until they earn promotion via a
formal design review. See the comment in `cmd/mallcop-academy/hard_constraints.go`.
