# CLAUDE.md — mallcop

> The ACTIVE Go OSS security scanner. Module `github.com/mallcop-app/mallcop`.
> Ships as a one-shot CLI (`cmd/mallcop`): scan → detect → committee → findings.
> No legion/automaton runtime — that scaffolding was removed; the product is the CLI.

## Cross-Repo Architecture

See ~/projects/mallcop-pro/CLAUDE.md for full cross-repo architecture, including:
- mallcop-pro tenant service (Forge integration, Polar checkout, donut billing)
- mallcop OSS CLI (connectors, detectors, skills, actors)
- Forge inference proxy (accounts, billing, metering, Bedrock routing)

## This Repo

mallcop is the standalone Go scanner. The runtime is the one-shot `cmd/mallcop`
binary — no external orchestrator:
- `core/` — pure product logic (detectors, committee agent, eval harness, pipeline).
  An import-lint (`core/lint`) bans any agent-framework / transport / vendor-SDK dep.
- `cmd/mallcop` — the CLI entrypoint (`scan`, `exam`, ...).
- `connect/` — connectors (github, file, ...).

## Related Items

- Parent work item: mallcoppro-eb1
- mallcop-connectors: ~/projects/mallcop-connectors
- mallcop-skills: ~/projects/mallcop-skills

## Spikes

Prior spike research is in docs/spikes/ — do not delete.
