# mallcop

> Open-source security monitoring for small cloud operators. AI-native. Go.

mallcop is a Go-native security monitoring CLI. It ingests your cloud and SaaS
audit events, runs 17 deterministic detectors that look for real-world attack
patterns, then drives each finding through an LLM-backed investigation cascade
(triage → investigate → deep panel → committee consensus) before paging a human.
Findings and resolutions are written to a git-native store, so every decision is
durable, replayable, and auditable. The rules corpus is embedded in the binary —
mallcop is a single standalone executable.

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

**1. Install mallcop** (see above).

**2. Scaffold a store and sample events:**

```bash
mallcop init
```

`init` creates a `store/` directory (the git-backed findings store) and a sample
`events.jsonl`, then prints the exact next-step commands below.

**3. Run a scan over the sample events:**

```bash
mallcop scan --events events.jsonl --store store
```

That's it — no config file. `scan` reads the events, runs the detectors, drives
findings through the cascade, and commits findings + resolutions into `store/`.
With no inference endpoint configured, every finding force-escalates (the
documented fail-safe), so the command works end to end with zero credentials.

**4. (Optional) Enable LLM-driven resolution.** Point mallcop at an inference
endpoint via the `MALLCOP_INFERENCE_URL` / `MALLCOP_API_KEY` pivot — a vendor URL
+ key for BYOK, or the Forge URL + a `mallcop-sk-*` tenant key for the metered
managed path:

```bash
export MALLCOP_INFERENCE_URL=https://api.mallcop.app
export MALLCOP_API_KEY=mallcop-sk-...
mallcop scan --events events.jsonl --store store
```

**5. Inspect what was recorded:**

```bash
mallcop status --store store
```

## Commands

| Command | Purpose |
|---------|---------|
| `mallcop scan` | Full agentic scan: connect → detect → cascade → store. Requires `--store`. |
| `mallcop detect` | Offline detection only. Reads events JSONL on stdin, writes findings JSONL on stdout. No inference key. |
| `mallcop init` | Scaffold a findings store + sample events and print runnable next steps. |
| `mallcop status` | Report findings/resolutions recorded in a store. Requires `--store`. |
| `mallcop config` | Print the effective scan config resolved from the environment. |

### `mallcop scan`

```bash
# File connector (default): scan a local events JSONL file
mallcop scan --events events.jsonl --store store

# GitHub connector (built into the core binary): scan a GitHub org's audit log
export GITHUB_APP_ID=...
export GITHUB_APP_PRIVATE_KEY=...      # PEM, or a path to it
export GITHUB_INSTALLATION_ID=...
mallcop scan --connector github --github-org my-org --store store
```

Flags: `--store` (required), `--events` (file path or `-` for stdin),
`--connector` (`file` | `github`), `--github-org`, `--baseline`, `--workers`,
`--json`, `--base-url`.

Exit codes: `0` no findings, `1` findings present, `2` scan failure.

## Architecture

```
mallcop scan
  → connector        — fetch/ingest audit events (file or github)
  → detectors        — 17 deterministic attack-pattern detectors
  → cascade          — triage → investigate → deep panel → committee consensus
  → git store        — durable, replayable findings + resolutions
```

The cascade resolves each finding through escalating tiers and ends in a
committee **consensus** vote: on every RESOLVE, the gate re-runs the cascade and
**any-escalate-wins** — a safety-first, asymmetric policy because a missed attack
(false negative) is catastrophic while an over-escalation merely pages a human.
The operator rules corpus is embedded in the binary, so the scan is fully
standalone — no external rules files to ship or keep in sync.

## Connectors

The core binary ships two **built-in** connectors:

- **file** (default) — reads normalized event JSONL from `--events`.
- **github** — pulls a GitHub org's audit log directly, using
  `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_INSTALLATION_ID`.

Additional connectors ship as **standalone binaries** in the sibling repo
[mallcop-app/mallcop-connectors](https://github.com/mallcop-app/mallcop-connectors).
Each emits event JSONL that you pipe into `mallcop scan --events -`:

```bash
mallcop-connector-aws-cloudtrail --region us-east-1 \
  | mallcop scan --events - --store store
```

Currently shipped standalone connectors: AWS CloudTrail, Azure Activity Log,
GCP Cloud Logging, GitHub Audit Log, M365 Management Activity, Okta System Log.

**Not yet ported:** `container_logs`, `supabase`, `vercel`.

## Detectors

17 deterministic detectors run on every scan (and via `mallcop detect`):

```
auth-failure-burst       config-drift            dependency-tamper
exfil-pattern            git-oops                injection-probe
log-format-drift         malicious-skill         new-actor
new-external-access      priv-escalation         rate-anomaly
secrets-exposure         unusual-login           unusual-resource-access
unusual-timing           volume-anomaly
```

Content-only detectors (e.g. `injection-probe`, `secrets-exposure`, `git-oops`,
`config-drift`, `dependency-tamper`, `malicious-skill`) fire without any history.
The baseline-dependent detectors (`new-actor`, `priv-escalation`, `unusual-login`,
`unusual-timing`, `volume-anomaly`, `rate-anomaly`, `exfil-pattern`) use an
optional `--baseline` JSON file for historical context.

## License

MIT. See [LICENSE](LICENSE).
