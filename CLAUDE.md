# CLAUDE.md — Mallcop

## Project

**Mallcop**: Open-source security monitoring for small cloud operators. AI-native — the primary user is an AI agent, not a human.

- **License**: Apache 2.0
- **Contributing**: See `CONTRIBUTING.md`
- `docs/product-vision.md` — what this is, why it exists, design principles
- `docs/design.md` — technical architecture, plugin contracts, schemas, operational model

## Language & Stack

- **Python** — rich API client libraries for Azure, GitHub, M365. Single `pip install mallcop` distribution.
- **CLI framework**: `click` or `typer`
- **Storage**: JSONL files (repo-native), in-memory SQLite as runtime query cache
- **Config**: YAML
- **No containers required to run** — mallcop is a CLI tool that runs anywhere Python runs

## Repo Structure

```
mallcop/
├── CLAUDE.md
├── README.md
├── LICENSE
├── pyproject.toml
├── docs/
│   ├── product-vision.md
│   └── design.md
├── src/
│   └── mallcop/
│       ├── __init__.py
│       ├── cli.py              # CLI entrypoint
│       ├── config.py           # Config loading, secret resolution
│       ├── store.py            # Store ABC + JsonlStore implementation
│       ├── baseline.py         # Baseline computation from events
│       ├── budget.py           # Token budget tracking, circuit breaker
│       ├── connectors/
│       │   ├── __init__.py
│       │   ├── _base.py        # ConnectorBase ABC
│       │   ├── _schema.py      # Event dataclass, manifest schema
│       │   └── azure/          # directory-with-manifest plugin
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── _base.py        # DetectorBase ABC
│       │   ├── _schema.py      # Finding dataclass, manifest schema
│       │   └── new_actor/      # directory-with-manifest plugin
│       ├── actors/
│       │   ├── __init__.py
│       │   ├── _base.py        # ActorBase ABC
│       │   ├── _schema.py      # Resolution schema, manifest schema
│       │   ├── runtime.py      # Actor invocation loop (LLM + tools)
│       │   ├── triage/         # directory-with-manifest plugin
│       │   └── notify_teams/   # directory-with-manifest plugin
│       ├── llm/
│       │   ├── __init__.py     # build_llm_client factory, exports
│       │   ├── anthropic.py    # AnthropicClient (direct API)
│       │   ├── bedrock.py      # BedrockClient (AWS SigV4)
│       │   ├── openai_compat.py # OpenAICompatClient
│       │   └── converters.py   # Message format converters
│       └── tools/
│           ├── __init__.py     # @tool decorator, registry
│           ├── events.py
│           ├── baseline.py
│           ├── findings.py
│           └── config.py
└── tests/
```

Each plugin (connector, detector, actor) is a directory containing `manifest.yaml` and Python implementation. See `docs/design.md` for plugin contracts and manifest schemas.

## Source of Truth Hierarchy

1. `docs/product-vision.md` — product direction and design principles
2. `docs/design.md` — technical architecture and contracts
3. `CLAUDE.md` — repo structure and development conventions

## Development

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest

# Run mallcop
mallcop --help

# Verify a plugin
mallcop verify --all
```

## Testing Requirements

**All code changes require tests. No exceptions.**

### Process: TDD Red-Green

1. Write the test first. Run it. It must fail (red).
2. Implement the code. Run the test. It must pass (green).
3. If you refactor, run the full suite. Everything must stay green.

### Test Layers

| Layer | Directory | What it tests | When to write |
|-------|-----------|--------------|---------------|
| **Unit** | `tests/unit/` | Individual functions, classes, methods in isolation | Every code change |
| **Integration** | `tests/integration/` | Components working together (store + baseline, connector + checkpoint) | Every epic |
| **Functional** | `tests/functional/` | End-to-end CLI workflows (`mallcop init`, `mallcop watch`, `mallcop review`) | Every use case |

### Rules

- **You own all failures.** There is no "pre-existing" failure. If a test fails, fix the code — never disable or skip the test.
- **Run the full suite before every commit.** `pytest` must be green. If it's not, you're not done.
- **Connectors use recorded fixtures.** No live API calls in tests. Record once, replay forever.
- **Use cases require functional tests.** A use case is not done until an automated test exercises the full scenario end-to-end.
- **Plugin contract tests validate manifests.** `mallcop verify` runs as part of the test suite for any plugin change.

### Test Structure

```
tests/
├── unit/
│   ├── test_store.py           # JsonlStore read/write
│   ├── test_baseline.py        # frequency tables, known entities
│   ├── test_budget.py          # circuit breaker, token caps
│   ├── test_config.py          # config loading, secret resolution
│   └── ...
├── integration/
│   ├── test_scan_pipeline.py   # connector → store → checkpoint
│   ├── test_detect_pipeline.py # store → baseline → detector → findings
│   ├── test_actor_runtime.py   # actor manifest → tool registry → LLM loop
│   └── ...
├── functional/
│   ├── test_uc_setup.py        # UC: init discovers environment, writes config
│   ├── test_uc_learning.py     # UC: learning period suppresses escalation
│   ├── test_uc_routine.py      # UC: watch runs full pipeline
│   ├── test_uc_intrusion.py    # UC: review + investigate workflow
│   ├── test_uc_scaffold.py     # UC: scaffold + verify for new plugin
│   ├── test_uc_status.py       # UC: external agent reads status/report
│   └── test_uc_deployment.py   # UC: GH Actions workflow structure
└── fixtures/
    ├── azure/                  # recorded Azure API responses
    └── ...
```

## Conventions

- Plugins follow directory-with-manifest pattern (see `docs/design.md` Plugin Architecture)
- All events normalize to common Event schema before storage
- CLI output is JSON by default (for AI consumption), with `--human` flag for readable output
- No external services required to run — everything is local except the platforms being monitored
- Tests use recorded API responses (fixtures), not live API calls
- Plugin contract tests are auto-generated from manifest declarations
