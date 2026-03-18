"""ProductionRunCapture — local telemetry capture for the Academy Flywheel.

Activated only when ``capture_telemetry: true`` is set in mallcop.yaml.
Captures are NEVER transmitted — local file write only.

Storage: ~/.mallcop/captures/YYYY-MM/cap-{capture_id}.jsonl
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["ProductionRunCapture", "save_capture", "is_capture_enabled"]

_DEFAULT_CAPTURES_DIR = Path.home() / ".mallcop" / "captures"


def _now_iso8601() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProductionRunCapture:
    """A single production security finding captured for the Academy Flywheel.

    Fields
    ------
    capture_id       : UUID4 string — unique identifier for this capture.
    captured_at      : ISO 8601 timestamp (UTC) of capture time.
    mallcop_version  : Version string from the running mallcop installation.
    tenant_id        : Opaque tenant identifier (sha256(root_path)[:16]).
    connector        : Connector name that produced the finding (e.g. "github").
    detector         : Detector name that triggered (e.g. "unusual_timing").
    finding_raw      : Full Finding dict as produced by the detector.
    events_raw       : List of raw Event dicts that informed the finding.
    baseline_raw     : Baseline snapshot at time of detection.
    connector_tool_calls : List of tool call records made by the connector agent.
    actor_chain      : Dict describing the triage/chain actor execution:
                         triage_action  (str)
                         chain_action   (str)
                         chain_reason   (str)
                         llm_calls      (list[dict])
                         total_tokens   (int)
    human_override   : Optional human override string (e.g. "dismiss").
    confidence_score : Float confidence score from the squelch model.
    """

    mallcop_version: str
    tenant_id: str
    connector: str
    detector: str
    finding_raw: dict[str, Any]
    events_raw: list[dict[str, Any]]
    baseline_raw: dict[str, Any]
    connector_tool_calls: list[dict[str, Any]]
    actor_chain: dict[str, Any]
    human_override: str | None
    confidence_score: float

    # Auto-populated fields
    capture_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    captured_at: str = field(default_factory=_now_iso8601)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "capture_id": self.capture_id,
            "captured_at": self.captured_at,
            "mallcop_version": self.mallcop_version,
            "tenant_id": self.tenant_id,
            "connector": self.connector,
            "detector": self.detector,
            "finding_raw": self.finding_raw,
            "events_raw": self.events_raw,
            "baseline_raw": self.baseline_raw,
            "connector_tool_calls": self.connector_tool_calls,
            "actor_chain": self.actor_chain,
            "human_override": self.human_override,
            "confidence_score": self.confidence_score,
        }


def save_capture(
    capture: ProductionRunCapture,
    base_dir: Path | None = None,
) -> Path:
    """Persist a capture to the local filesystem (append-only JSONL).

    The file is written to:
        <base_dir>/YYYY-MM/cap-{capture_id}.jsonl

    Returns the path of the file written.
    """
    dest_root = base_dir or _DEFAULT_CAPTURES_DIR
    # Monthly subdir based on captured_at
    try:
        ts = datetime.fromisoformat(capture.captured_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)
    month_dir = dest_root / ts.strftime("%Y-%m")
    month_dir.mkdir(parents=True, exist_ok=True)

    filename = f"cap-{capture.capture_id}.jsonl"
    dest = month_dir / filename
    line = json.dumps(capture.to_dict(), separators=(",", ":")) + "\n"
    try:
        with open(dest, "a") as f:
            f.write(line)
    except OSError:
        pass  # Captures are best-effort
    return dest


def is_capture_enabled(config: dict[str, Any]) -> bool:
    """Return True if capture_telemetry is explicitly set to True in config."""
    return bool(config.get("capture_telemetry", False))
