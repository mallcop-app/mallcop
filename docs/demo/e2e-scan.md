# Demo: a real `mallcop scan` that triages a finding end-to-end

This is a cold-user, copy-pasteable demo of the **production** scan path:

```
raw events (JSONL)  →  connect  →  detect (the real detector fleet)
                    →  cascade (triage → investigate → escalate)  →  git store
```

It uses ONLY findings the **real `core/detect` fleet actually produces** over the
sample events — so what you see is true production behaviour, not an eval
injection. This is the SAME `pipeline.Run` code path the end-to-end eval harness
exercises (`mallcop-eval -mode e2e`), so the demo and the validation share one
code path.

The sample data is deliberately chosen so the detectors fire: an **unknown actor**
(`ext-contractor-9f`, absent from the baseline's `known_actors`) performs a
**privilege grant** (`role_assignment` with `role_name: admin`). Two real detectors
trip on it — `new-actor` and `priv-escalation` — guaranteeing a finding (avoiding
the zero-finding traps the detect-fidelity map exposes for scenarios whose detector
does not exist).

## Files (in this directory)

### `events.jsonl` — 2 events, one suspicious, one benign

```jsonl
{"id":"evt-001","source":"github","type":"role_assignment","actor":"ext-contractor-9f","timestamp":"2026-06-18T03:14:07Z","org":"acme-corp","payload":{"role_name":"admin","permission_level":"admin","target_user":"acme-corp/payments-api","action":"add_role_assignment","ip":"203.0.113.77"}}
{"id":"evt-002","source":"github","type":"push","actor":"ci-bot","timestamp":"2026-06-18T09:02:11Z","org":"acme-corp","payload":{"action":"push","target":"acme-corp/website","branch":"main"}}
```

- `evt-001` — `ext-contractor-9f` (a **novel** actor) self-grants the **admin**
  role on `payments-api`. Fires `new-actor` **and** `priv-escalation`.
- `evt-002` — `ci-bot` (a **known** actor) pushes to `main`. Benign — no finding.

### `baseline.json` — makes the contractor genuinely novel

```json
{
  "known_users": {},
  "known_actors": ["ci-bot", "deploy-svc"],
  "frequency_tables": {
    "github:push:ci-bot": 4821,
    "github:role_assignment:admin-user": 12
  },
  "actor_roles": {
    "ci-bot": ["read"],
    "deploy-svc": ["write"]
  }
}
```

`ext-contractor-9f` is NOT in `known_actors` and has NO `admin` role in
`actor_roles`, so both detectors treat the grant as new + unauthorized.

## Run it

The `{base_url, key}` pivot points either at your model vendor (BYOK) or at Forge
(the metered managed path). `mallcop-sk-*` is a Forge tenant key.

```bash
export MALLCOP_INFERENCE_URL=https://forge.example/v1
export MALLCOP_API_KEY=mallcop-sk-...
export MALLCOP_MODEL=glm-5

mallcop scan \
  --events   docs/demo/events.jsonl \
  --baseline docs/demo/baseline.json \
  --store    /tmp/mallcop-demo-store \
  --json
```

Then read the triaged verdicts back from the git store (the store writes via git
plumbing, so the records are read from the committed blob, not a work-tree file):

```bash
git -C /tmp/mallcop-demo-store show HEAD:resolutions.jsonl
```

## Expected output

The JSON summary (exit code **1** = findings present):

```json
{
  "events_scanned": 2,
  "findings_detected": 2,
  "escalated": 2,
  "resolved": 0
}
```

The triaged findings in `resolutions.jsonl` — both escalated for the novel actor:

```jsonl
{"finding_id":"finding-evt-001","action":"escalate","actor":"ext-contractor-9f","source":"detector:new-actor","reason":"..."}
{"finding_id":"finding-evt-001","action":"escalate","actor":"ext-contractor-9f","source":"detector:priv-escalation","reason":"Privilege escalation / role grant / permission-boundary change always requires human audit. ... No LLM involved."}
```

`priv-escalation` is a **hard-constraint floor route**: it escalates in code with
**no model in the loop** (a privilege/boundary change always gets a human audit) —
so this finding escalates even with no inference key set. `new-actor` is routed
through the **cascade** (triage → investigate → escalate) against your configured
model; with a real model the agent investigates the actor's history before
deciding. Either way the novel admin grant reaches a human.

## Why this matches the e2e validation

`mallcop scan` and `mallcop-eval -mode e2e` call the **same** `core/pipeline.Run`
with the **same** production `core/toolrun.Runner`. The demo's single finding flows
through connect → detect → cascade → store exactly as each of the 56 e2e corpus
scenarios does. The e2e harness additionally reports **detect-fidelity** — how many
corpus findings the detector fleet even reproduces — which is the honest measure of
whether the validated agent-reasoning accuracy transfers to a live scan.
