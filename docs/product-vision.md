# Mallcop — Product Vision

## One-liner

Security monitoring for small cloud operators. AI-native. Self-hosted. Near-$0.

## The Problem

Every small team running cloud services has the same problem:

- Too small for a SIEM
- Too small for a SOC
- Too exposed to ignore
- Existing tools are enterprise-priced or require full-time ops staff

You're running containers, a bank account, GitHub repos, M365 email — and nobody's watching any of it. If someone pushed through a locked door, you wouldn't even know.

The security industry sells solutions to enterprises. Small operators get nothing.

## The Insight

AI agents are already operating infrastructure for small teams. They deploy containers, manage repos, handle finances. But they have no security awareness — no tool to reach for when they sense exposure.

**The user is the AI agent, not the human.** The human is the escalation path.

This is the beancount of security monitoring. Beancount didn't compete with QuickBooks — it gave programmers (and their tools) plain-text double-entry accounting. Mallcop doesn't compete with CrowdStrike — it gives AI agents a CLI tool that watches an environment and tells them when something's wrong.

### Agentic Escalation

Mallcop doesn't just notify — it investigates. When something looks wrong, findings flow through an actor chain: a cheap triage agent resolves the obvious false positives, an investigation agent digs deeper into ambiguous cases, and only genuinely unresolved findings reach a human. Each tier gets progressively more capable models and more tools. The human sees a curated batch digest with full investigation annotations — not a firehose of raw alerts.

Mallcop is OpenClaw for security. OpenClaw's power isn't that it sends emails — it's that you give it tools and a goal, and the LLM figures out how to compose them. The plugin system is the product, not the plugins. Mallcop works the same way: connectors, detectors, actors, and tools are all extensible plugins. When you add a new connector, you don't write new triage rules — the actor runtime already knows how to investigate findings from sources it's never seen, because it reasons over tool outputs, not hardcoded playbooks. The platform's intelligence scales with the model, not with the codebase.

## What It Does

1. **Connects** to the platforms small teams actually use (Azure, AWS, GitHub, M365, Vercel, container logs, and more)
2. **Learns** what normal looks like by accumulating baseline activity over time
3. **Detects** anomalies — new admin, unfamiliar IP, unusual transaction, configuration drift, unexpected access patterns
4. **Escalates** to humans through messaging channels, but only when something actually matters

## Design Principles

### AI is the user
CLI-first. Structured JSON output. Designed for agents (Claude, OpenClaw, etc.) to run, interpret, and act on. No dashboards. No web UI. The human never touches mallcop directly — they just stop getting robbed.

### Plugin-first architecture
Connectors, detectors, actors, and tools are all plugins following a directory-with-manifest pattern. Each plugin is a directory containing a `manifest.yaml` and Python implementation. The architecture is optimized for supervised coding agent development: strict base classes, manifest-declared capabilities, auto-generated contract tests, and single-command verification (`mallcop scaffold` + `mallcop verify`).

### Self-learning
Mallcop accumulates a model of "normal" through frequency tables and entity tracking, not ML. First 14 days are learning mode. After that, deviations from baseline are flagged. The baseline updates continuously (sliding window) so seasonal patterns are absorbed. Manual feedback (`mallcop ack`) teaches it what's expected.

### Self-discovering
`mallcop init` probes the environment. It finds what's connected — cloud subscriptions, repos, email tenants, banking APIs, running containers — and writes a config file. Point it at an environment and it figures out what to watch.

### Repo-native
A mallcop deployment is a git repo. Events, findings, baseline data, config, and actor instructions all live in the repo as JSONL and YAML files. Like beancount stores ledger files in git, mallcop stores security state in git. This means state survives ephemeral compute (GitHub Actions, container jobs), is version-controlled (`git log events/`), portable (clone and you have everything), and backed up (push to remote). There is no external database.

### Near-$0 to run
No paid dependencies. Steampipe (free) for posture scanning. Platform APIs are free (Azure Activity Log, AWS CloudTrail, M365 Audit, GitHub events, Vercel audit log). Storage is files in a git repo. Runs on a cron in GitHub Actions (free tier), a container job, or any Linux box.

The only variable cost is LLM API calls for actor investigation. Mallcop controls this with hard budget ceilings: a volume circuit breaker that bypasses actors entirely when finding volume spikes (the most expensive scenario costs zero tokens), per-run and per-finding token caps, and severity-priority spending. `mallcop init` estimates steady-state costs up front. `mallcop status --costs` shows actual spend trends. Worst-case monthly cost at default budget settings on haiku: under $1. Cost is visible, predictable, and capped — not open-ended.

### Opinionated about one job
Mallcop does security monitoring. It doesn't do deployment, doesn't do CI/CD, doesn't do project management. Like beancount, it does one thing and does it well.

## How It Works

### Connectors
Each platform gets a connector that knows how to authenticate, poll for events, and normalize them into mallcop's common event format.

Connectors:
- **Azure** — Activity Log (control plane), Container Apps access logs, Cosmos DB diagnostics, Defender free tier findings
- **AWS CloudTrail** — SigV4-authenticated LookupEvents, 10 event types including IAM changes, security group modifications, S3 policy changes
- **GitHub** — webhook events, Dependabot alerts, security alerts, org audit log, permission changes
- **M365** — Management Activity API (sign-ins, admin actions, Exchange events). 7-day API window requires regular polling.
- **Vercel** — deployment events and audit log, 8 event types
- **Container Logs** — Log Analytics queries for container app stdout/stderr (works with Azure Container Apps, including scaled-to-zero apps)

Future connectors: GCP, Cloudflare, Railway, Render, Mercury (banking), custom webhook receiver for arbitrary services.

### Baseline Model
- **Frequency tables**: event type × source × actor × time-of-day/day-of-week
- **Known entities**: IP addresses, user agents, actor IDs, resource names seen before
- **Relationships**: which actors normally touch which resources
- **Configuration snapshots**: resource settings at last scan (for drift detection)

### Anomaly Detection (rule-based)
- New actor (never-seen user, IP, API key)
- Privilege escalation (new admin role, new repo collaborator with write)
- Unusual timing (normally 9-5 events at 3am)
- Volume anomalies (10x normal rate for a source)
- Financial anomalies (new recipient, transfer above historical max)
- Configuration drift (resource settings changed from last scan)
- Container probing (unusual request patterns to self-hosted services)

### Escalation
Findings flow through a configurable actor chain. Severity is a routing key — it determines which actor handles the finding, not what the engine does with it.

```yaml
routing:
  info: null        # logged, no actor invoked
  warn: triage      # autonomous triage
  critical: triage  # same chain — or configure differently per your risk tolerance
```

The actor chain is operator-configured: triage, investigate, respond, notify — in whatever order and depth makes sense. Actors can be AI agents (with tools and models) or notification channels (Teams, Slack, email). Unresolved findings escalate to the next actor in the chain.

Humans receive a batch digest with full investigation annotations — not raw alerts. Messages are short and actionable, designed so a human reading a phone notification gets the point in 2 seconds.

### Dual-mode investigation
**Autonomous**: actor chain runs on a schedule within budget controls. Handles routine triage unattended. **Interactive**: a human opens an agent session (Claude Code, OpenClaw) and uses mallcop's CLI to investigate findings directly — `mallcop review` loads the playbook and findings, the session's token budget covers inference. Autonomous handles the 90%. Interactive handles the deep dives.

### CLI Interface

```
# Core pipeline
mallcop init                    # Discover environment, write config, estimate costs
mallcop scan                    # Poll all connectors, store events
mallcop detect                  # Run detectors against baseline, flag anomalies
mallcop escalate                # Invoke actor chain on open findings
mallcop watch [--dry-run]       # scan + detect + escalate (cron-friendly)

# Investigation (interactive mode)
mallcop review                  # Load playbook + all open findings for session agent
mallcop investigate <id>        # Deep context for one finding
mallcop finding <id>            # Full finding detail + annotation trail
mallcop events [filters]        # Query events by finding, actor, source, time
mallcop baseline [filters]      # Query baseline by actor, entity
mallcop annotate <id> "<text>"  # Add investigation note
mallcop ack <id>                # Resolve finding, update baseline

# Operational
mallcop report [filters]        # Output findings (JSON default, --human for readable)
mallcop status [--costs]        # Event counts, spend trends

# Development
mallcop scaffold <type> <name>  # Generate plugin stubs
mallcop verify [path|--all]     # Validate plugin against contracts
```

### Scheduled Operation

```cron
# Run every 6 hours
0 */6 * * * cd /path/to/my-security && mallcop watch && git add -A && git commit -m "watch" && git push
```

Or as a GitHub Actions scheduled workflow (free tier), Azure Container Apps job, or any CI/CD cron trigger. The deployment repo is checked out, mallcop runs, results are committed and pushed. Mallcop reads and writes files — the scheduler handles the git lifecycle.

## Comparison to Existing Tools

| Tool | What it does | Why it doesn't fit |
|------|-------------|-------------------|
| **Wazuh** | Full SIEM/XDR | Overkill. Needs 4-6 GB RAM, constant maintenance. |
| **Sentinel** | Microsoft's SIEM | $4.30/GB. Not free. |
| **Steampipe** | SQL queries against cloud APIs | Posture only (config checks). No event monitoring, no learning, no alerting. Mallcop uses it as a component. |
| **Prowler** | Cloud security scanning | Posture only. Point-in-time checks, no continuous monitoring. |
| **CrowdStrike/Datadog/etc.** | Enterprise security platforms | $$$. Wrong market entirely. |
| **OpenClaw** | General-purpose AI agent | Not security-specific. Mallcop is to security what OpenClaw is to personal automation — same extensible AI-native architecture, applied to a specific domain. OpenClaw would reach for mallcop as its security tool. |

## First User

3DL (Third Division Labs) — a two-person AI-directed holding company running:
- Azure Container Apps (Rudi, OpenSign)
- Cosmos DB
- M365
- GitHub (6+ repos)
- Vercel (web deployments)

Mallcop is deployed and monitoring this real environment.

## Scaling Path

Mallcop's plugin interfaces are storage-agnostic. The MVP stores everything as JSONL in a git repo. For larger operations, the storage backend swaps to persistent SQLite or PostgreSQL — no plugin code changes. Connectors, detectors, actors, and tools work identically regardless of whether events live in JSONL files or a database.

| Scale | Storage | Scheduling |
|-------|---------|-----------|
| Small (solo founder) | JSONL in git repo | Cron / GH Actions, every 6h |
| Medium (growing startup) | Persistent SQLite or PostgreSQL | Cron, every 30min |
| Large (real SOC) | PostgreSQL / TimescaleDB | Daemon or message queue |

## Market

Every solo founder, small agency, or indie hacker running cloud services. Every AI agent operating infrastructure. The "too small for enterprise tools, too exposed for nothing" gap.

This is not a SaaS product. It's open-source infrastructure — like beancount, like Steampipe, like OpenClaw. It spreads through AI agents recommending it and developers starring it.

## Name

Mallcop. Not a SWAT team. Not a SOC. Just a guy on a segway who knows the building and notices when something's off.
