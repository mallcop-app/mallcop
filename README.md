# mallcop

Security monitoring for small cloud operators. AI-native. Self-hosted. Near-$0.

## What is this?

Mallcop watches your cloud infrastructure and tells you when something's wrong. It's designed for AI agents to operate -- not humans clicking dashboards.

Think of it as the security guard at your mall. Not a SWAT team. Just someone who knows the building, notices when something's off, and calls you when it matters.

## Who is it for?

- Solo founders running cloud services
- Small teams too small for a SIEM, too exposed for nothing
- AI agents operating infrastructure that need security awareness

## What does it monitor?

- **Azure** -- activity log, container apps, Cosmos DB, Defender findings
- **AWS CloudTrail** -- IAM changes, security group modifications, console logins, S3 policy changes
- **GitHub** -- repo changes, permission changes, security alerts, Actions
- **Microsoft 365** -- sign-ins, admin actions, email events
- **Vercel** -- deployments, audit log, team membership changes
- **Container Logs** -- container app stdout/stderr via Log Analytics

## Install

```bash
pip install mallcop
```

## Quickstart

### 1. Initialize

Create a new git repo (or use an existing one) as your deployment repo, then run init:

```bash
mkdir my-security && cd my-security
git init
mallcop init
```

`mallcop init` discovers your environment -- probes for Azure subscriptions, GitHub orgs, and other connected platforms. It writes a `mallcop.yaml` config file and reports estimated costs.

All output is JSON by default (for AI agents). Use `--human` for readable output on any command.

### 2. First scan

```bash
mallcop scan
mallcop detect
```

`mallcop scan` polls all configured connectors and stores events in `events/` as JSONL files.

`mallcop detect` runs detectors against stored events and writes findings to `findings.jsonl`.

During the first 14 days (the baseline learning period), detectors log findings as informational only -- no escalation, no alerts. This lets mallcop learn what "normal" looks like for your environment.

### 3. Automated monitoring

For ongoing monitoring, use `mallcop watch` which runs scan + detect + escalate in one command:

```bash
mallcop watch
```

Or with `--dry-run` to skip actor escalation:

```bash
mallcop watch --dry-run
```

### 4. Set up scheduled runs

The recommended setup is a GitHub Actions workflow that runs every 6 hours. An example workflow is included in the package at `mallcop/templates/github-actions-example.yml`:

```yaml
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
      - run: |
          git config user.name "mallcop"
          git config user.email "mallcop@noreply"
          git add -A
          git diff --cached --quiet || git commit -m "mallcop watch $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push
```

Configure the required secrets in your GitHub repo settings. You can also use cron or any other scheduler -- mallcop is just a CLI tool.

### 5. Investigation

When findings need attention, use the investigation commands in a Claude Code session (or any AI agent):

```bash
# Orient: see all open findings with context
mallcop review

# Drill down into a specific finding
mallcop investigate <finding-id>

# Query events and baseline
mallcop events --finding <id>
mallcop baseline --actor <actor>

# Report on findings
mallcop report --status open --severity warn,critical
```

`mallcop review` loads all open findings, groups by severity, and outputs everything an agent needs to start investigating -- including POST.md playbooks and suggested commands.

## Deployment repo structure

After init and a few watch runs, your deployment repo looks like this:

```
my-security/
  mallcop.yaml              # config: connectors, routing, secrets, budget
  checkpoints.yaml          # connector cursors (last poll position)
  events/                   # append-only JSONL, partitioned by source and month
    azure-2026-03.jsonl
    github-2026-03.jsonl
  findings.jsonl            # detector output
  costs.jsonl               # per-run token usage and cost tracking
  baseline.json             # computed baseline state (known actors, frequencies)
  actors/                   # actor instructions (POST.md playbooks)
    triage/
      POST.md
```

- **events/** -- raw events from each connector, partitioned by source and month
- **findings.jsonl** -- detector output: what looks unusual
- **baseline.json** -- what "normal" looks like: known actors, frequency tables, entity relationships
- **costs.jsonl** -- token usage and cost per escalation run
- **mallcop.yaml** -- configuration: which connectors, routing rules, budget limits

Everything is git-tracked. `git log events/` shows when events were ingested. `git diff findings.jsonl` shows what changed between runs.

## CLI commands

```
# Core pipeline
mallcop init                        # discover environment, write config, estimate costs
mallcop scan                        # poll all connectors, store events
mallcop detect                      # run detectors against events
mallcop escalate                    # invoke actor chain on open findings
mallcop watch [--dry-run]           # scan + detect + escalate (cron-friendly)

# Investigation (interactive mode)
mallcop review                      # orient: POST.md + all open findings + commands
mallcop investigate <finding-id>    # drill down: deep context for one finding
mallcop finding <finding-id>        # full finding detail + annotation trail
mallcop events [--finding] [--actor] [--source] [--hours] [--type]
mallcop report [--status] [--severity] [--since]
mallcop baseline [--actor] [--entity]
mallcop status [--costs]            # operational status and cost trends

# Finding management
mallcop annotate <finding-id> <text>  # add investigation note to a finding
mallcop ack <finding-id> [--reason]   # resolve finding, update baseline

# App integration
mallcop discover-app <app-name>     # sample container logs, output structured context

# Development
mallcop scaffold <type> <name>      # generate plugin directory with stubs
mallcop verify [--all]              # validate plugins against contracts
```

All commands output JSON by default. Use `--human` for readable output.

## Cost

Near-$0. Mallcop is free and open source. The platform APIs it monitors are free tier. The only cost is LLM inference for the triage actor during escalation, controlled by configurable budget limits (default: 50k tokens/run). `mallcop init` estimates your steady-state costs based on discovered resources.

## License

MIT
