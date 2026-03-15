# Contributing Detectors to Mallcop

Mallcop detectors are rules that identify suspicious or anomalous behavior in security event streams. This guide explains how to write and contribute new detectors to the Mallcop OSS project.

## Why Community Detectors Matter

The DeclarativeDetector YAML format is human-readable and writable. Community-contributed detectors follow the same directory-with-manifest pattern as built-in detectors. This creates a flywheel: the community writes detectors manually, Pro users generate them automatically via OSINT research. Same format, different input mechanism. Community contributions validate and discipline the schema — if only machines write detectors, the format drifts toward whatever the LLM finds convenient.

## Detector Structure

Every detector lives in its own directory under `src/mallcop/detectors/` and contains:

```
src/mallcop/detectors/my-detector/
├── manifest.yaml          # Metadata and configuration
└── detector.py            # Python implementation
```

Choose one path:

### Option A: Custom Detector (Python Class)

Write a `detector.py` file that implements the `DetectorBase` interface:

```python
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding

class MyDetector(DetectorBase):
    def relevant_sources(self) -> list[str] | None:
        # Return list of connector names this detector operates on,
        # or None to receive events from all sources
        return ["azure", "github"]

    def relevant_event_types(self) -> list[str] | None:
        # Return list of event types this detector cares about,
        # or None to receive all event types
        return ["role_assignment", "permission_change"]

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        # Analyze events and return findings
        # Each finding represents something that needs attention
        findings = []
        # ... your detection logic ...
        return findings
```

The `Baseline` object provides historical context:
- `frequency_tables`: Dictionary of `"source:event_type:actor"` → count mappings
- `known_entities`: Known actors, targets, IP addresses, etc.
- `relationships`: Actor→target relationships observed in the baseline

### Option B: Declarative Detector (YAML Rules)

For simple patterns, use DeclarativeDetector YAML format. Your `manifest.yaml` declares `sources` and `event_types`, but you don't write `detector.py`. Instead, the Mallcop engine interprets YAML rules at detection time.

See the Declarative Detector reference below.

## Manifest Format

Every detector must include `manifest.yaml`:

```yaml
name: my-detector              # Unique identifier (kebab-case)
description: What this detects # Human-readable description
version: 0.1.0                 # Semantic version
sources:                       # Which connectors produce relevant events
  - azure
  - github
event_types:                   # Which event types matter for this detector
  - role_assignment
  - permission_change
severity_default: critical     # Default severity: info | warn | critical
```

### Field Requirements

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Unique detector identifier (e.g., `privilege-escalation`) |
| `description` | string | Yes | Clear, concise description of what it detects |
| `version` | string | Yes | Semantic version (e.g., `0.1.0`) |
| `sources` | list of strings or `"*"` | Yes | Connector names (azure, github, m365, etc.) or `"*"` for all |
| `event_types` | list of strings or `"*"` | Yes | Event type names (e.g., `role_assignment`) or `"*"` for all |
| `severity_default` | string | Yes | `info`, `warn`, or `critical` |
| `config` | mapping | No | Optional detector-specific configuration (for custom detectors) |

### Wildcard Sources and Event Types

```yaml
sources: "*"           # Receive events from all connectors
event_types: "*"       # Receive all event types
```

**Important**: A detector declaring `sources: "*"` and `event_types: "*"` should only use common event fields (`actor`, `target`, `source`, `event_type`, `action`). Avoid accessing connector-specific metadata.

## Declarative Detector YAML Rules

If you choose Option B, your detector's behavior is defined entirely in YAML. Each rule has a `condition` that Mallcop evaluates at detection time.

### Condition Types

#### count_threshold

Fires when N+ events occur within a time window, grouped by one or more fields.

```yaml
condition:
  type: count_threshold
  group_by: ["actor"]           # Group events by actor(s)
  window_minutes: 30             # Sliding window size
  threshold: 10                  # Fire when count >= this
```

Example: "10+ authentication failures from one actor in 30 minutes"

Optional fields:
- `group_by`: List of field names (default: `["actor"]`). Supports:
  - Top-level event fields: `actor`, `target`, `source`, `event_type`, `action`
  - Nested metadata: `metadata.user_agent`, `metadata.ip_address`, etc.

#### new_value

Fires when a field value hasn't been seen in the baseline.

```yaml
condition:
  type: new_value
  field: ip_address             # Which field to check
```

Example: "Actor using a new IP address not in baseline"

The `field` can be:
- Top-level: `actor`, `target`, `source`, `action`
- Nested in metadata: `metadata.user_agent`, `metadata.ip_address`

Field mappings to baseline known_entities:
- `target` → `targets`
- `actor` → `actors`
- `metadata.ip_address` → `ips`
- `metadata.user_agent` → `user_agents`
- `metadata.ip` → `ips`
- `source` → `sources`
- `action` → `actions`

#### volume_ratio

Fires when current event volume deviates significantly from baseline.

```yaml
condition:
  type: volume_ratio
  ratio: 2.0                    # Fire when current > 2.0 * baseline
  filter:                       # Optional: only count matching events
    action: "write"
    severity: "critical"
```

Example: "Write operations are 5x more frequent than baseline"

Optional fields:
- `filter`: Mapping of field name → value. Events must match all filters to be counted.

#### regex_match

Fires when a field matches a regex pattern.

```yaml
condition:
  type: regex_match
  field: metadata.command      # Which field to search
  pattern: "(rm|drop|delete).*--force"  # Regex pattern (raw string)
```

Example: "Command contains destructive operations with `--force`"

The pattern is compiled as Python regex (re.compile). Use raw strings to avoid escape issues.

## Directory Walkthrough

Let's build a detector from scratch.

### Step 1: Create the Directory

```bash
mkdir -p src/mallcop/detectors/unusual-login-time
cd src/mallcop/detectors/unusual-login-time
```

### Step 2: Create manifest.yaml

```yaml
name: unusual-login-time
description: Flags sign-in events at unusual times (e.g., 3 AM for an 9-to-5 user)
version: 0.1.0
sources:
  - azure
  - m365
event_types:
  - sign_in
  - login
severity_default: warn
config:
  unusual_hours: [0, 1, 2, 3, 4, 5]  # UTC hours considered unusual
```

### Step 3: Create detector.py

```python
"""Detects sign-in events at unusual times."""

import uuid
from datetime import datetime, timezone
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

class UnusualLoginTimeDetector(DetectorBase):
    def __init__(self):
        # Default unusual hours (UTC)
        self.unusual_hours = [0, 1, 2, 3, 4, 5]

    def relevant_sources(self) -> list[str] | None:
        return ["azure", "m365"]

    def relevant_event_types(self) -> list[str] | None:
        return ["sign_in", "login"]

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        findings = []

        for evt in events:
            hour = evt.timestamp.hour
            if hour in self.unusual_hours:
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    timestamp=datetime.now(timezone.utc),
                    detector="unusual-login-time",
                    event_ids=[evt.id],
                    title=f"Unusual sign-in time: {evt.actor} at {evt.timestamp.strftime('%H:%M')}",
                    severity=Severity.WARN,
                    status=FindingStatus.OPEN,
                    annotations=[],
                    metadata={"actor": evt.actor, "hour": hour},
                ))

        return findings
```

### Step 4: Create __init__.py (minimal)

```python
"""Unusual login time detector."""
```

## Testing Your Detector

### Unit Tests

Create a test file in `tests/unit/`:

```python
"""Tests for unusual-login-time detector."""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from mallcop.schemas import Baseline, Event, Severity

def _make_event(event_type: str, actor: str, hour: int) -> Event:
    ts = datetime(2024, 3, 15, hour=hour, tzinfo=timezone.utc)
    return Event(
        id=f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=ts,
        ingested_at=ts,
        source="azure",
        event_type=event_type,
        actor=actor,
        action="login",
        target="https://outlook.office365.com",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )

def test_unusual_login_time_fires():
    from mallcop.detectors.unusual_login_time.detector import UnusualLoginTimeDetector

    det = UnusualLoginTimeDetector()
    baseline = Baseline(frequency_tables={}, known_entities={}, relationships={})

    # Sign-in at 3 AM (unusual)
    events = [_make_event("sign_in", "alice", hour=3)]
    findings = det.detect(events, baseline)

    assert len(findings) == 1
    assert findings[0].actor == "alice"

def test_normal_login_time_ignores():
    from mallcop.detectors.unusual_login_time.detector import UnusualLoginTimeDetector

    det = UnusualLoginTimeDetector()
    baseline = Baseline(frequency_tables={}, known_entities={}, relationships={})

    # Sign-in at 2 PM (normal)
    events = [_make_event("sign_in", "alice", hour=14)]
    findings = det.detect(events, baseline)

    assert len(findings) == 0
```

### Run Verification

Verify your detector passes the contract validation:

```bash
cd ~/projects/mallcop
mallcop verify detectors/unusual-login-time
```

Expected output:

```
✓ unusual-login-time (detector): PASS
```

Run the full test suite to catch any integration issues:

```bash
pytest
```

## PR Requirements

Before submitting a pull request, ensure:

1. **manifest.yaml is present** with all required fields
   - `name`, `description`, `version`
   - `sources`, `event_types`, `severity_default`

2. **detector.py** (for custom detectors) or valid YAML rules (for declarative)
   - Classes inherit from `DetectorBase`
   - Methods implement required interface

3. **Verification passes**
   ```bash
   mallcop verify detectors/<your-detector-name>
   ```

4. **Tests pass**
   ```bash
   pytest
   ```

5. **All existing tests still pass**
   - Run `pytest` in the repo root
   - CI enforces this on PR submission

6. **Description explains the detector**
   - What behavior does it flag?
   - Why does it matter for security?
   - What are common false positives?

## PR Template

When submitting a detector PR, use this template:

```markdown
## New Detector: [detector-name]

### What it detects

[Brief description of the anomaly or threat]

### Severity

[info | warn | critical]

### Sources

[Which connectors provide relevant events]

### Why it matters

[Why this detection is important for security]

### False positives

[Known cases where the detector might fire incorrectly]

### Checklist

- [ ] `manifest.yaml` present with all required fields
- [ ] `mallcop verify detectors/<name>` passes
- [ ] Full test suite passes (`pytest`)
- [ ] New tests added for the detector logic
- [ ] Description explains what the detector catches and why
```

## Common Patterns

### Detect New Actors

```python
def detect(self, events, baseline):
    known_actors = set(baseline.known_entities.get("actors", []))
    findings = []
    for evt in events:
        if evt.actor not in known_actors:
            findings.append(Finding(...))
    return findings
```

### Detect Privilege Escalation

Look for `role_assignment`, `admin_action`, `permission_change` events with role names containing "admin", "owner", "write".

### Detect Unusual Volume

Compare current event count to baseline frequency tables:

```python
def detect(self, events, baseline):
    current_count = len(events)
    baseline_count = sum(
        count for key, count in baseline.frequency_tables.items()
        if "my_event_type" in key
    )
    if baseline_count > 0 and current_count > baseline_count * 3:
        # 3x spike detected
        return [Finding(...)]
    return []
```

## Publishing Your Detector

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-detector`
3. Add your detector directory with `manifest.yaml` and `detector.py`
4. Add tests in `tests/unit/`
5. Verify: `mallcop verify detectors/my-detector && pytest`
6. Commit and push
7. Open a PR with the template above
8. Respond to review feedback

Reviewers will check:
- Does the manifest validate?
- Does the logic make security sense?
- Are there edge cases or false positive risks?
- Does it match the existing detector style?

---

**Questions?** Open an issue or start a discussion in the GitHub repo.
