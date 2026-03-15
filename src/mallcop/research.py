"""OSINT research pipeline: read advisories, generate DeclarativeDetector YAML.

This module implements the `mallcop research` command backend. An LLM agent
reads advisory summaries and writes DeclarativeDetector YAML rules for new
threats relevant to the operator's configured connectors.

Flow:
    1. Load intel manifest (which advisories have already been processed)
    2. Filter candidates to only unworked advisories
    3. For each new advisory, call LLM with a structured prompt
    4. Parse the LLM response:
       - YAML → write to plugins/detectors/<name>/manifest.yaml
       - NOT_RELEVANT → record in manifest with reason, no file written
       - PYTHON (when allow_python=True) → write .py file to detector dir
       - PYTHON (when allow_python=False) → reject, record as skipped
    5. Update intel manifest after each advisory

LLM response formats (the agent must follow these conventions):
    YAML detector:   Raw YAML content starting with "name:" (or a YAML dict)
    Not relevant:    Line starting with "NOT_RELEVANT:" followed by reason
    Python detector: Line starting with "PYTHON:<detector-name>" followed
                     by Python code (only allowed when allow_python=True)
"""

from __future__ import annotations

import ast
import logging
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger(__name__)

from mallcop.intel_manifest import IntelEntry, filter_new, save_entry
from mallcop.llm_types import LLMClient


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Advisory:
    """A single OSINT advisory to research.

    Attributes:
        id: Unique advisory identifier (e.g. "CVE-2026-1234", "GHSA-xxxx-yyyy").
        source: Where the advisory came from ("nvd", "github-advisory", etc.).
        summary: Human-readable description of the threat.
    """
    id: str
    source: str
    summary: str


@dataclass
class ResearchConfig:
    """Configuration for the research pipeline.

    Attributes:
        allow_python: If True, the LLM agent may produce Python detector files
            (detector.py) in addition to declarative YAML. Default False for
            security: YAML-only detectors are sandboxed by the declarative
            interpreter; Python detectors run arbitrary code.
    """
    allow_python: bool = False


@dataclass
class ResearchResult:
    """Summary of what was researched and generated in a run.

    Attributes:
        advisories_checked: Total number of advisories passed in.
        advisories_new: Number not yet in the intel manifest (actually processed).
        detectors_generated: Number of detector files successfully written.
        detectors_skipped: Number that were irrelevant or rejected (no detector written).
    """
    advisories_checked: int
    advisories_new: int
    detectors_generated: int
    detectors_skipped: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def filter_unworked_advisories(manifest_path: Path, advisories: list[Advisory]) -> list[Advisory]:
    """Return only advisories not yet recorded in the intel manifest.

    Args:
        manifest_path: Path to intel-manifest.jsonl.
        advisories: Candidate advisories to check.

    Returns:
        Subset of advisories whose IDs are not in the manifest.
    """
    candidate_ids = [a.id for a in advisories]
    new_ids = set(filter_new(manifest_path, candidate_ids))
    return [a for a in advisories if a.id in new_ids]


def reject_python_output(filename: str, allow_python: bool) -> None:
    """Raise ValueError if the filename is a Python file and allow_python is False.

    Args:
        filename: The output filename proposed by the LLM.
        allow_python: Whether Python detector files are permitted.

    Raises:
        ValueError: If filename ends in .py and allow_python is False.
    """
    if filename.endswith(".py") and not allow_python:
        raise ValueError(
            f"LLM attempted to write a python file ({filename}) but "
            "research.allow_python is False. Set allow_python: true in mallcop.yaml "
            "to enable Python detector generation."
        )


def _slugify(name: str) -> str:
    """Convert a detector name to a filesystem-safe directory name.

    Replaces spaces and underscores with hyphens, lowercases, strips non-alnum.
    """
    slug = name.lower().strip()
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"[^a-z0-9\-]", "", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def write_detector_yaml(detectors_dir: Path, name: str, detector_data: dict[str, Any]) -> Path:
    """Write a detector manifest.yaml to the correct directory.

    Creates <detectors_dir>/<slug>/manifest.yaml.

    Args:
        detectors_dir: Root directory for detectors (e.g. plugins/detectors/).
        name: Detector name (used to form the directory slug).
        detector_data: Parsed YAML dict to write.

    Returns:
        Path to the written manifest.yaml.
    """
    slug = _slugify(name)
    detector_dir = detectors_dir / slug
    detector_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = detector_dir / "manifest.yaml"
    manifest_path.write_text(yaml.dump(detector_data, default_flow_style=False))
    return manifest_path


_BLOCKED_MODULES = frozenset({
    "os", "subprocess", "socket", "shutil", "ctypes",
    "multiprocessing", "signal", "webbrowser", "http",
    "ftplib", "smtplib", "telnetlib", "xmlrpc",
    "importlib", "code", "codeop", "compile", "compileall",
})


def check_python_safety(python_code: str) -> list[str]:
    """AST-check LLM-generated Python for blocked imports and unsafe calls.

    Returns a list of violation descriptions. Empty list means the code passed.
    """
    try:
        tree = ast.parse(python_code)
    except SyntaxError as e:
        return [f"SyntaxError: {e}"]

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _BLOCKED_MODULES:
                    violations.append(f"blocked import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in _BLOCKED_MODULES:
                    violations.append(f"blocked import from: {node.module}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval", "__import__"):
                violations.append(f"blocked builtin call: {node.func.id}()")
    return violations


def _write_detector_python(detectors_dir: Path, name: str, python_code: str) -> Path:
    """Write a Python detector file after safety checks.

    Creates <detectors_dir>/<slug>/detector.py. The code is AST-checked
    for blocked imports and unsafe calls before writing.

    Args:
        detectors_dir: Root directory for detectors.
        name: Detector name (used to form the directory slug).
        python_code: Python source code for the detector.

    Returns:
        Path to the written detector.py.

    Raises:
        ValueError: If the code fails safety checks.
    """
    violations = check_python_safety(python_code)
    if violations:
        raise ValueError(
            f"LLM-generated Python detector failed safety check: "
            f"{'; '.join(violations)}"
        )
    slug = _slugify(name)
    detector_dir = detectors_dir / slug
    detector_dir.mkdir(parents=True, exist_ok=True)
    py_path = detector_dir / "detector.py"
    py_path.write_text(python_code)
    _log.warning(
        "Wrote LLM-generated Python detector to %s. "
        "Review before deployment.", py_path
    )
    return py_path


def _build_research_prompt(
    advisory: Advisory,
    connector_names: list[str],
) -> str:
    """Build the LLM prompt for researching a single advisory.

    Args:
        advisory: The advisory to analyze.
        connector_names: List of connector names configured for this operator
            (used to determine relevance).

    Returns:
        System prompt string for the LLM.
    """
    connectors_str = ", ".join(connector_names) if connector_names else "none configured"
    return textwrap.dedent(f"""\
        You are a security researcher generating Mallcop detection rules.

        Your task: analyze the following security advisory and decide whether it is
        relevant to the operator's environment. If relevant, generate a Mallcop
        DeclarativeDetector YAML rule that would catch exploitation or indicators
        of compromise.

        Operator's configured connectors: {connectors_str}

        Advisory ID: {advisory.id}
        Source: {advisory.source}
        Summary: {advisory.summary}

        Response format — choose EXACTLY ONE:

        1. If the advisory IS relevant to the configured connectors, output ONLY a
           YAML document with these required fields:
               name: <detector-slug>          # kebab-case, e.g. "cve-2026-1234-rce"
               description: <one-line desc>
               version: "0.1.0"
               sources:                       # list of connector names this applies to
                 - <connector>
               event_types:                   # list of event_type strings
                 - <event_type>
               severity_default: <critical|warn|info>
               condition:
                 type: <count_threshold|new_value|volume_ratio|regex_match>
                 # condition fields appropriate for the chosen type

        2. If the advisory is NOT relevant to any of the configured connectors,
           respond with a line starting with:
               NOT_RELEVANT: <brief reason>

        Do not include any explanation outside of the format above.
    """)


def _parse_llm_response(text: str) -> tuple[str, str | None, str | None]:
    """Parse the LLM response text into (response_type, detector_name, content).

    Returns:
        Tuple of (response_type, detector_name, content) where:
        - response_type is "yaml", "not_relevant", or "python"
        - detector_name is the detector name (for yaml/python) or None
        - content is the YAML/Python source or the not-relevant reason
    """
    stripped = text.strip()

    # Check for NOT_RELEVANT
    if stripped.upper().startswith("NOT_RELEVANT:"):
        reason = stripped[len("NOT_RELEVANT:"):].strip()
        return "not_relevant", None, reason

    # Check for PYTHON:<name>
    python_match = re.match(r"^PYTHON:([^\n]+)\n(.+)", stripped, re.DOTALL)
    if python_match:
        name = python_match.group(1).strip()
        code = python_match.group(2)
        return "python", name, code

    # Assume YAML
    try:
        parsed = yaml.safe_load(stripped)
        if isinstance(parsed, dict) and "name" in parsed:
            return "yaml", parsed["name"], stripped
    except yaml.YAMLError:
        pass

    # Unrecognised — treat as not-relevant with a note
    return "not_relevant", None, f"LLM response was not parseable as YAML or NOT_RELEVANT: {stripped[:100]}"


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------


def run_research(
    advisories: list[Advisory],
    manifest_path: Path,
    detectors_dir: Path,
    llm_client: LLMClient,
    config: ResearchConfig,
    connector_names: list[str],
) -> ResearchResult:
    """Run the OSINT research pipeline.

    For each new advisory (not yet in the intel manifest):
    - Ask the LLM to analyze the threat and generate a DetlarativeDetector YAML
    - Parse the response
    - Write the detector file (if generated)
    - Update the intel manifest

    Args:
        advisories: Candidate advisories to research.
        manifest_path: Path to intel-manifest.jsonl.
        detectors_dir: Where to write generated detector directories.
        llm_client: LLM client to use for generating detectors.
        config: Research configuration (allow_python, etc.).
        connector_names: Operator's configured connector names (for relevance filtering).

    Returns:
        ResearchResult summarising what was done.
    """
    advisories_checked = len(advisories)
    new_advisories = filter_unworked_advisories(manifest_path, advisories)
    advisories_new = len(new_advisories)
    detectors_generated = 0
    detectors_skipped = 0

    for advisory in new_advisories:
        system_prompt = _build_research_prompt(advisory, connector_names)
        response = llm_client.chat(
            model="claude-haiku-4-5-20251001",
            system_prompt=system_prompt,
            messages=[{"role": "user", "content": f"Research advisory: {advisory.id}"}],
            tools=[],
        )

        response_type, detector_name, content = _parse_llm_response(response.text)

        if response_type == "not_relevant":
            # Record in manifest — irrelevant, no detector
            save_entry(manifest_path, IntelEntry(
                id=advisory.id,
                source=advisory.source,
                researched_at=datetime.now(timezone.utc),
                detector=None,
                reason=content or "not relevant to configured connectors",
            ))
            detectors_skipped += 1

        elif response_type == "yaml":
            try:
                detector_data = yaml.safe_load(content)
                slug = _slugify(detector_name or detector_data.get("name", advisory.id))
                write_detector_yaml(detectors_dir, slug, detector_data)
                save_entry(manifest_path, IntelEntry(
                    id=advisory.id,
                    source=advisory.source,
                    researched_at=datetime.now(timezone.utc),
                    detector=slug,
                ))
                detectors_generated += 1
            except Exception as e:
                # Failed to write — record as skipped with reason
                save_entry(manifest_path, IntelEntry(
                    id=advisory.id,
                    source=advisory.source,
                    researched_at=datetime.now(timezone.utc),
                    detector=None,
                    reason=f"YAML write failed: {e}",
                ))
                detectors_skipped += 1

        elif response_type == "python":
            try:
                reject_python_output("detector.py", config.allow_python)
                slug = _slugify(detector_name or advisory.id)
                _write_detector_python(detectors_dir, slug, content or "")
                save_entry(manifest_path, IntelEntry(
                    id=advisory.id,
                    source=advisory.source,
                    researched_at=datetime.now(timezone.utc),
                    detector=slug,
                ))
                detectors_generated += 1
            except ValueError as e:
                # Python rejected (allow_python=False or safety check failed)
                save_entry(manifest_path, IntelEntry(
                    id=advisory.id,
                    source=advisory.source,
                    researched_at=datetime.now(timezone.utc),
                    detector=None,
                    reason=f"Python detector rejected: {e}",
                ))
                detectors_skipped += 1

    return ResearchResult(
        advisories_checked=advisories_checked,
        advisories_new=advisories_new,
        detectors_generated=detectors_generated,
        detectors_skipped=detectors_skipped,
    )
