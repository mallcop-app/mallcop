# Academy Exam

The **Academy Exam** is mallcop's built-in benchmark for validating the AI reasoning quality of your deployment. It runs 54+ pre-built scenarios through your actor chain with canned data and grades how well the AI investigates and resolves each finding.

It is designed for Claude Code users who want to validate, tune, and improve mallcop's AI behavior without needing to generate real security events.

---

## What it is

The Academy Exam drives your triage and investigate actors through canned security scenarios — each with synthetic events, baseline data, and a known-correct outcome. An LLM-as-judge then grades each run on:

- **Reasoning quality** (1–5): Does the agent cite specific evidence?
- **Investigation thoroughness** (1–5): Does it use the right tools and follow up?
- **Resolve quality** (1–5): Can a human spot-check the resolution in 30 seconds?
- **Escalation actionability** (1–5): Can a human decide what to do in under 1 minute?

A scenario **passes** when investigation thoroughness ≥ 3 and reasoning quality ≥ 3. A wrong action with shallow reasoning is flagged as a **warn** (lucky guess), not a pass.

---

## Running the exam

```bash
# Run all scenarios (requires ANTHROPIC_API_KEY or claude-code backend)
mallcop exam run

# Filter to a specific failure mode
mallcop exam run --tag KA

# Run a single scenario by ID
mallcop exam run --scenario KA-01

# Use Claude Code instead of direct API
mallcop exam run --backend claude-code

# Human-readable output
mallcop exam run --human

# Save output for improvement loop
mallcop exam run > results.json
```

Via pytest (for CI or development):

```bash
pytest -m academy_exam    # preferred
pytest -m shakedown       # backward-compatible alias
```

---

## The improvement loop

Run the exam → read grades → fix the relevant file → re-run the exam.

```bash
# 1. Run the exam and save results
mallcop exam run > results.json

# 2. Analyze failures and get fix suggestions
mallcop improve --from-exam results.json

# 3. Apply the suggested changes to triage/POST.md, investigate/POST.md,
#    or your detectors/*.yaml files.

# 4. Re-run the exam to verify improvement
mallcop exam run
```

The `improve` command groups failures by fix target (triage prompt, investigate prompt, declarative detector, etc.) and tells you which file to edit and what the failure pattern is. It does not modify files automatically — that's a future feature.

### Fix targets

| Fix target | File to edit | When it fires |
|---|---|---|
| `triage_prompt` | `src/mallcop/actors/triage/POST.md` | Triage made wrong routing decision |
| `investigate_prompt` | `src/mallcop/actors/investigate/POST.md` | Investigation reached wrong conclusion |
| `declarative_detector` | `src/mallcop/detectors/*.yaml` | Wrong event triggered the finding |
| `parser_template` | `apps/*/parser.yaml` | App log parsing misread the event |
| `connector_tool` | `connectors/*/tools.py` | Tool returned wrong data shape |

---

## Failure modes

Scenarios are tagged by the failure mode they test:

| Tag | Failure mode | What it tests |
|---|---|---|
| `KA` | Known-actor abuse | Legitimate user doing something unusual |
| `AE` | Automated execution | Scripts/bots vs. human activity |
| `CS` | Credential sharing | Shared accounts, service account misuse |
| `NE` | New entity | First-seen actor, resource, or pattern |
| `VN` | Volume anomaly | Spike in normal-looking events |
| `TT` | Timing trap | Off-hours activity that's actually scheduled |

Filter by tag to focus on a specific weakness:

```bash
mallcop exam run --tag KA --human
```

---

## For Claude Code users

The Academy Exam is designed to be used with Claude Code as your improvement co-pilot:

1. **Install mallcop from source**:
   ```bash
   git clone https://github.com/mallcop-app/mallcop
   cd mallcop && pip install -e ".[dev]"
   ```

2. **Run the exam**:
   ```bash
   mallcop exam run --backend claude-code > results.json
   ```

3. **Ask Claude Code to help**:
   > "Here are my mallcop exam results: [paste results.json]. The KA scenarios are failing. What should I change in triage/POST.md?"

4. **Re-run to verify**:
   ```bash
   mallcop exam run --tag KA --human
   ```

Claude Code can read the actor prompts, scenario YAML files, and evaluator output directly — it has everything it needs to propose targeted improvements.

---

## Backends

| Backend | How to use | When to use |
|---|---|---|
| `anthropic` (default) | Set `ANTHROPIC_API_KEY` | Pay-as-you-go API |
| `claude-code` | Claude Max subscription | No API key needed |
| `bedrock` | Set `AWS_REGION` + IAM credentials | AWS-native deployments |
| `openai-compat` | Set `OPENAI_BASE_URL` + `OPENAI_API_KEY` | OpenAI or compatible endpoints |
| `managed` | Set `MALLCOP_SERVICE_URL` + `MALLCOP_SERVICE_TOKEN` | Mallcop Pro managed inference |

```bash
mallcop exam run --backend claude-code --model sonnet
```

---

## Scenarios directory

Scenarios live in `tests/shakedown/scenarios/`. Each is a YAML file with:

- Finding + events (canned data)
- Baseline (frequency tables, known entities)
- Expected outcome (chain action, triage action)
- Ground truth rubric (what sound reasoning should conclude)
- Connector tool stubs (canned API responses)

To add a scenario, copy an existing YAML file and adjust the data. The harness picks up all `*.yaml` files in the directory tree automatically.

See `tests/shakedown/scenario.py` for the full schema.
