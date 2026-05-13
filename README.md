# mallcop

> Open-source security monitoring for small cloud operators. AI-native. Go.

mallcop is a Go-native security monitoring CLI. It plugs into your cloud audit
logs (AWS, Azure, GCP, GitHub, M365, Okta), runs detectors that look for
real-world attack patterns, and uses LLM-driven investigation tools to
triage findings before paging a human.

## Status

**v0.6.0** is the first release on this Go codebase. It supersedes the Python
implementation at [mallcop-app/mallcop-py](https://github.com/mallcop-app/mallcop-py).
Python users: see [Migrating from Python mallcop](#migrating-from-python-mallcop-05x) below.

## Install

**Go install (latest):**

```bash
go install github.com/mallcop-app/mallcop/cmd/mallcop@latest
```

**Release binaries:**

Pre-built binaries for Linux, macOS, and Windows are attached to each
[GitHub release](https://github.com/mallcop-app/mallcop/releases). Download
the archive for your platform, extract, and place `mallcop` on your `PATH`.

## Quickstart

**1. Install mallcop:**

```bash
go install github.com/mallcop-app/mallcop/cmd/mallcop@latest
```

**2. Set up a connector.**

Connectors live in the sibling repo
[mallcop-app/mallcop-connectors](https://github.com/mallcop-app/mallcop-connectors).
Follow that repo's README to install and configure the connector for your
platform (e.g. AWS CloudTrail, GitHub Audit Log).

**3. Run a scan:**

```bash
mallcop scan
```

mallcop reads `charts/vertical-slice.toml` by default. Pass `--chart` to point
at a different chart file.

```bash
mallcop scan --chart charts/my-stack.toml --timeout 15m --json
```

Use `mallcop init` to scaffold a config directory in the current folder.

## Architecture

```
mallcop CLI (cmd/mallcop)
  → connectors       — fetch cloud audit events
  → detectors        — pattern-match for attack indicators
  → investigate-tools — LLM-driven triage
  → notifiers        — page humans on confirmed findings
```

### Binaries

| Binary | Purpose |
|--------|---------|
| `cmd/mallcop` | Primary user-facing CLI (`scan`, `init`, `status`, `config`) |
| `cmd/mallcop-academy` | Scenario-based evaluation harness for detectors |
| `cmd/mallcop-investigate-tools` | Investigation actor surface (LLM tool calls) |
| `cmd/detector-*` | 13 detector binaries (config-drift, dependency-tamper, exfil-pattern, git-oops, injection-probe, malicious-skill, new-actor, priv-escalation, rate-anomaly, secrets-exposure, unusual-login, unusual-timing, volume-anomaly) |
| `cmd/notify-{email,slack,teams,telegram}` | Outbound notification channels |
| `cmd/baseline` | Baseline snapshot management |
| `cmd/mallcop-checklist-verify` | Post-scan checklist verification |
| `cmd/mallcop-coverage-tripwire` | Coverage enforcement |
| `cmd/mallcop-exam-report` | Academy exam report generation |
| `cmd/mallcop-finding-context` | Finding enrichment context |

### Key packages

| Package | Role |
|---------|------|
| `pkg/event` | Shared event types across connectors and detectors |
| `pkg/finding` | Finding schema and severity levels |
| `pkg/baseline` | Baseline snapshot storage and diffing |
| `pkg/resolution` | Finding resolution tracking |
| `internal/exam` | Academy exam runner shared types |

## Connectors

Connector binaries live in a sibling repo:
[mallcop-app/mallcop-connectors](https://github.com/mallcop-app/mallcop-connectors).

Currently shipped: AWS CloudTrail, Azure Activity Log, GCP Cloud Logging,
GitHub Audit Log, M365 Management Activity, Okta System Log.

## Migrating from Python mallcop (0.5.x)

The Go rewrite is a clean break. There is no automated migration path.

**Connectors not yet ported to Go:** `container_logs`, `supabase`, `vercel`,
`openclaw_config_drift`. If you depend on these, stay on Python 0.5.x until
Go equivalents ship.

**CLI surface changes:**
- `mallcop scan` replaces `mallcop run`
- `mallcop init` scaffolds a TOML chart + `output/` directory (replaces `mallcop.yaml` + `.mallcop/`)
- Patrol scheduler, chat REPL, daemon mode, and baseline ack/feedback/scaffold/verify/research/contribute are not yet ported

**Config format changed:** YAML `mallcop.yaml` → TOML chart files under `charts/`.
No automated conversion. Reconfigure from scratch using `mallcop init`.

**License changed:** Apache-2.0 → MIT.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
