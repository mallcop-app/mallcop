# Mallcop Quickstart

## What it is

Mallcop is a security monitoring CLI for small cloud operators. It connects to the platforms you already use, learns what normal looks like, and tells you when something's off.

The primary user is an AI agent (Claude Code, OpenClaw, etc.). The human is the escalation path — you get a Teams message when something actually matters, not a firehose of raw alerts.

## Architecture in 60 seconds

```
                    ┌─────────────┐
                    │  mallcop    │
                    │  watch      │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌──────────┐
         │  scan   │ │ detect  │ │ escalate │
         └────┬────┘ └────┬────┘ └────┬─────┘
              │            │            │
    ┌─────────┴──────┐     │     ┌──────┴──────────┐
    │   Connectors   │     │     │   Actor Chain    │
    │                │     │     │                  │
    │  azure         │     │     │  triage (LLM)    │
    │  github        │     │     │    ↓ escalate    │
    │  m365          │     │     │  investigate     │
    │  container-logs│     │     │    ↓ escalate    │
    └───────┬────────┘     │     │  notify-teams    │
            │              │     └──────────────────┘
            ▼              │
    ┌───────────────┐      │
    │    Events     │      │
    │  (JSONL files)│──────┘
    └───────────────┘      │
                           ▼
                   ┌───────────────┐
                   │   Detectors   │
                   │               │
                   │  new-actor    │
                   │  priv-escal.  │
                   │  auth-burst   │
                   │  unusual-time │
                   │  volume-anom. │
                   │  inject-probe │
                   │  + 3 more     │
                   └───────┬───────┘
                           ▼
                   ┌───────────────┐
                   │   Findings    │
                   │  (JSONL file) │
                   └───────────────┘
```

**Connectors** poll platform APIs and normalize events into a common schema.
**Detectors** compare events against a learned baseline and flag anomalies.
**Actors** investigate findings using LLM reasoning and tools, then resolve or escalate.

Everything is a plugin. Every plugin is a directory with a `manifest.yaml` and Python code.

## Install

```bash
pip install mallcop
```

## Setup

### The easy way: let Claude Code do it

If you're comfortable giving Claude Code access to an Azure account with Global Administrator (or at least Application Administrator + RBAC admin), the setup is one conversation:

> "Set up mallcop to monitor my Azure subscription."

Claude Code will:
1. Create a deployment repo
2. Create a least-privilege service principal (`mallcop-monitor`)
3. Assign the right roles (Reader, Monitoring Reader, Log Analytics Reader)
4. Run `mallcop init` to discover your environment
5. Write `mallcop.yaml` and `.env`
6. Run the first `mallcop scan` and `mallcop detect`

That's how mallcop was actually deployed for its first user. The human's only job was approving the tool calls.

### The manual way

If you'd rather set things up yourself:

**1. Create a deployment repo**

Mallcop stores all state — events, findings, baseline, config — as files in a git repo. This is the deployment repo. It's separate from mallcop's source code.

```bash
mkdir my-security && cd my-security
git init
```

**2. Create a service principal (Azure)**

Mallcop needs read-only access to your Azure subscription:

```bash
az ad sp create-for-rbac --name mallcop-monitor \
  --role Reader \
  --scopes /subscriptions/<your-sub-id>
```

Then grant additional roles on the same subscription:

```bash
SUB=/subscriptions/<your-sub-id>
az role assignment create --assignee <sp-client-id> --role "Monitoring Reader" --scope $SUB
az role assignment create --assignee <sp-client-id> --role "Log Analytics Reader" --scope $SUB
```

If you run Container Apps, also grant per resource group:

```bash
az role assignment create --assignee <sp-client-id> --role "Reader" --scope $SUB/resourceGroups/<rg-name>
```

**3. Set up credentials**

Create a `.env` file in your deployment repo (git-ignored):

```bash
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-sp-client-id
AZURE_CLIENT_SECRET=your-sp-secret
ANTHROPIC_API_KEY=sk-ant-...
TEAMS_WEBHOOK_URL=https://...   # see "Escalation" below
```

**4. Initialize**

```bash
mallcop init
```

This probes your environment — finds Azure subscriptions, GitHub orgs, container apps — and writes `mallcop.yaml`. Review it, then:

```bash
mallcop scan          # poll connectors, store events
mallcop detect        # run detectors, write findings
mallcop status --human  # check everything looks right
```

The first 14 days are learning mode. Detectors flag findings as informational while mallcop builds a baseline of what "normal" looks like.

### 5. Set up escalation

Mallcop validates that every finding has a path to a human. If escalation is broken, `mallcop status` tells you:

```
ESCALATION: BROKEN
  Routing 'critical' → 'triage' → ... → channel 'notify-teams': webhook_url not configured
```

To fix this, create a Teams webhook:

1. In Teams, go to **Workflows** (hamburger menu)
2. Search for **"Post to a channel when a webhook request is received"**
3. Configure it, copy the URL
4. Add to `.env`: `TEAMS_WEBHOOK_URL=https://...`

Verify: `mallcop status --human` should show `Escalation: ok`.

### 6. Automate

Run `mallcop watch` on a schedule. The simplest setup is a cron job or GitHub Actions workflow:

```yaml
# .github/workflows/watch.yml
name: mallcop-watch
on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install mallcop
      - run: mallcop watch
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
      - run: |
          git config user.name "mallcop"
          git config user.email "mallcop@noreply"
          git add -A
          git diff --cached --quiet || git commit -m "watch $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push
```

`mallcop watch` = scan + detect + escalate in one command. Results are committed and pushed — your deployment repo is the audit trail.

## How the actor chain works

When `mallcop escalate` runs, findings flow through an actor chain:

```
Finding (severity: warn)
  → triage (Sonnet, read-only, 3 iterations max)
      "Known contractor login during business hours → resolved"

Finding (severity: critical)
  → triage (Sonnet)
      "Unknown actor at 3 AM, can't determine intent → escalated"
  → investigate (Sonnet, read+write, 10 iterations max)
      "Checked baseline, searched events, no match → escalated"
  → notify-teams (channel actor)
      "POST to Teams webhook with batch digest"
```

**Triage** gets pre-loaded context (the finding's events and baseline data) and resolves the obvious cases in one LLM call. Most findings stop here.

**Investigate** gets the same pre-loaded context plus write tools (annotate findings) for deeper analysis. Escalates to human only when evidence is insufficient.

**Notify-teams** formats a batch digest and POSTs to your Teams webhook. You get a phone notification with the finding title, severity, and investigation notes — not raw alerts.

Cost is controlled by budget ceilings: per-finding token caps, per-run limits, and a circuit breaker that bypasses actors entirely during volume spikes. `mallcop status --costs` shows actual spend.

## Interactive investigation

When a finding reaches you, open a Claude Code session in your deployment repo:

```bash
cd my-security
claude

# Inside the session:
mallcop review                          # see all open findings
mallcop investigate <finding-id>        # deep context for one finding
mallcop events --finding <finding-id>   # raw events
mallcop baseline --actor <actor-email>  # what's normal for this actor
mallcop annotate <id> "checked: legitimate contractor"
mallcop ack <id>                        # resolve + update baseline
```

`mallcop review` outputs everything an agent needs: the playbook, open findings grouped by severity, and suggested commands. The agent investigates, you confirm.

## Extending mallcop

Everything is a plugin. Four types:

| Type | What it does | Example |
|------|-------------|---------|
| **Connector** | Polls a platform API, normalizes events | `azure`, `github`, `m365` |
| **Detector** | Compares events to baseline, flags anomalies | `new-actor`, `volume-anomaly` |
| **Actor** | Investigates findings using LLM + tools | `triage`, `investigate` |
| **Tool** | Gives actors capabilities (read events, check baseline) | `read-events`, `check-baseline` |

### Adding a plugin

```bash
mallcop scaffold connector cloudflare
mallcop scaffold detector unusual-geo
mallcop scaffold actor deep-investigate
mallcop scaffold tool query-dns
```

This generates a directory with `manifest.yaml`, implementation stubs, and contract tests. Edit the stubs, then verify:

```bash
mallcop verify plugins/connectors/cloudflare/
```

### Plugin structure

Every plugin is a directory:

```
connectors/
  cloudflare/
    manifest.yaml     # declares capabilities, auth, event types
    connector.py      # implements ConnectorBase
    tools.py          # investigation tools for this connector
    fixtures/         # recorded API responses for tests
    tests.py          # contract tests
```

The manifest is both documentation and contract — it declares what the plugin does, and `mallcop verify` checks that the implementation matches.

### What makes this extensible

Mallcop doesn't hardcode detection rules or investigation playbooks. When you add a new connector, the existing detectors and actors already work with it — because they reason over normalized events and baseline data, not connector-specific logic.

Add a Cloudflare connector that emits `login` events with an `actor` field, and the `new-actor` detector catches unfamiliar actors automatically. The triage actor investigates using the same tools (read-events, check-baseline) without knowing Cloudflare exists.

This is the same pattern as OpenClaw: the plugin system is the product. The LLM figures out how to compose tools it's never seen before, because it reasons over tool outputs — not hardcoded playbooks.

### Deployment-level plugins

Drop plugin directories into `plugins/` in your deployment repo to add connectors, detectors, or actors without forking mallcop:

```
my-security/
  plugins/
    connectors/
      my-custom-api/
        manifest.yaml
        connector.py
    detectors/
      my-compliance-check/
        manifest.yaml
        detector.py
  mallcop.yaml
  events/
  ...
```

Deployment plugins take precedence over built-in ones. This lets you customize or override anything without touching mallcop's source.

## Deployment repo layout

After a few watch runs:

```
my-security/
  mallcop.yaml              # config: connectors, routing, budget
  .env                      # secrets (git-ignored)
  checkpoints.yaml          # connector cursors (last poll position)
  baseline.json             # learned "normal": actors, frequencies, relationships
  findings.jsonl            # detector output
  costs.jsonl               # per-run token usage
  events/
    azure-2026-03.jsonl     # partitioned by source and month
    github-2026-03.jsonl
    container-logs-2026-03.jsonl
```

Everything is a file. `git log events/` shows ingestion history. `git diff findings.jsonl` shows what changed. Clone the repo and you have the complete security state.

## CLI reference

```
# Core pipeline
mallcop init                        # discover environment, write config
mallcop scan                        # poll connectors, store events
mallcop detect                      # run detectors against baseline
mallcop escalate                    # invoke actor chain on findings
mallcop watch [--dry-run]           # scan + detect + escalate

# Investigation
mallcop review                      # playbook + open findings for agent
mallcop investigate <finding-id>    # deep context for one finding
mallcop finding <finding-id>        # finding detail + annotation trail
mallcop events [--finding] [--source] [--since]
mallcop baseline [--actor] [--entity]
mallcop annotate <id> "<text>"      # add investigation note
mallcop ack <id>                    # resolve finding, update baseline
mallcop report [--status] [--severity] [--since]
mallcop status [--costs]            # health check + cost trends

# Development
mallcop scaffold <type> <name>      # generate plugin stubs
mallcop verify [--all]              # validate plugins against contracts
mallcop discover-app <app-name>     # sample container logs, output context
```

All commands output JSON by default (for AI agents). Use `--human` for readable output.

## Cost

Mallcop itself is free and open source. Platform APIs are free tier. The only variable cost is LLM inference during escalation:

- **Triage + investigation**: ~14k tokens per finding (Sonnet, with pre-packed context)
- **Steady state** (10 findings/week): ~$3/month
- **Cost per finding**: ~$0.08

Budget controls: per-finding token caps, per-run limits, circuit breaker that bypasses actors entirely during volume spikes. `mallcop status --costs` shows actual spend. `mallcop init` estimates costs up front.
