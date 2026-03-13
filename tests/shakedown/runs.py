"""Structured JSONL output recorder for shakedown runs."""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    try:
        return bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL
            ).strip()
        )
    except Exception:
        return True


class RunRecorder:
    """Records per-scenario grades to a JSONL file under runs/."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.run_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.git_sha = _git_sha()
        self.git_dirty = _git_dirty()
        self.output_dir = output_dir or Path("runs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._file = self.output_dir / f"{self.run_id}.jsonl"

    def record(
        self,
        grade: Any,
        result: Any,
        scenario: Any,
        model: str,
        backend: str,
        judge_model: str,
    ) -> None:
        """Append one JSONL record for a completed scenario evaluation."""
        fix_target_value = None
        if grade.fix_target is not None:
            fix_target_value = grade.fix_target.value

        record = {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "git_sha": self.git_sha,
            "git_dirty": self.git_dirty,
            "model": model,
            "backend": backend,
            "judge_model": judge_model,
            "scenario_id": scenario.id,
            "verdict": grade.verdict.value,
            "action_correct": grade.action_correct,
            "reasoning_quality": grade.reasoning_quality,
            "investigation_thoroughness": grade.investigation_thoroughness,
            "fix_target": fix_target_value,
            "fix_hint": grade.fix_hint,
            "tokens": grade.tokens,
            "latency_ms": sum(c.latency_ms for c in result.llm_calls),
            "llm_calls": len(result.llm_calls),
            "triage_action": result.triage_action,
            "chain_action": result.chain_action,
        }
        with open(self._file, "a") as f:
            f.write(json.dumps(record) + "\n")
