"""Three-pass anonymizer for ProductionRunCapture records.

Anonymization is deterministic within a single capture (same username always
maps to the same synthetic label). The original capture dict is never mutated.

Pass 1 — Identity replacement:
  usernames   → user_A, user_B, ... (ordered by first appearance)
  org names   → org_ALPHA, org_BETA, ...
  repo names  → repo_1, repo_2, ...
  IP addresses → 10.0.0.1, 10.0.0.2, ...
  email addrs → user@example.com (all become the same canonical placeholder)
  resource IDs → synthetic equivalents
  timestamps   → shifted by random-seeded offset, relative timing preserved

Pass 2 — Baseline scrubbing:
  actor names in known_entities and actor_frequency keys replaced with
  the same synthetic labels established in Pass 1.

Pass 3 — Tool response scrubbing:
  Apply Pass 1 replacements to connector tool call response_raw fields.
  Truncate non-security-relevant string fields longer than 200 chars.
"""
from __future__ import annotations

import copy
import hashlib
import re
import string
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = ["Anonymizer", "anonymize_capture", "is_test_environment"]

# ---------------------------------------------------------------------------
# Label sequences
# ---------------------------------------------------------------------------

_USER_LABELS = [
    f"user_{c}" for c in string.ascii_uppercase
] + [f"user_{c1}{c2}" for c1 in string.ascii_uppercase for c2 in string.ascii_uppercase]

_ORG_LABELS = [
    "org_ALPHA", "org_BETA", "org_GAMMA", "org_DELTA", "org_EPSILON",
    "org_ZETA", "org_ETA", "org_THETA", "org_IOTA", "org_KAPPA",
]

_REPO_LABELS = [f"repo_{i}" for i in range(1, 1000)]

# ---------------------------------------------------------------------------
# Regex patterns for identity detection
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# ---------------------------------------------------------------------------
# Test environment detection
# ---------------------------------------------------------------------------

_TEST_HOSTNAME_PATTERNS = re.compile(
    r"(?i)\b(test|ci|dev|localhost|staging|sandbox|fake|mock|runner|ephemeral)\b"
)


def is_test_environment(hostname: str) -> bool:
    """Return True if hostname looks like a test/CI environment."""
    return bool(_TEST_HOSTNAME_PATTERNS.search(hostname))


# ---------------------------------------------------------------------------
# Main anonymizer
# ---------------------------------------------------------------------------

class Anonymizer:
    """Deterministic three-pass anonymizer for a single capture dict."""

    def __init__(self, capture: dict[str, Any]) -> None:
        self._original = capture
        # Maps original value → synthetic label
        self.identity_map: dict[str, str] = {}
        self._user_counter = 0
        self._org_counter = 0
        self._repo_counter = 0
        self._ip_counter = 0
        # Timestamp shift — derived from capture_id for determinism
        self._ts_offset: timedelta | None = None
        self._build_ts_offset()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        """Return a fully anonymized deep copy of the capture dict."""
        data = copy.deepcopy(self._original)

        # Pre-scan to build identity map in encounter order
        self._prescan(data)

        # Pass 1: identity replacement on finding_raw + events_raw + actor_chain
        data["finding_raw"] = self._anon_dict(data.get("finding_raw", {}))
        data["events_raw"] = [
            self._anon_event(e) for e in data.get("events_raw", [])
        ]
        if "actor_chain" in data:
            data["actor_chain"] = self._anon_actor_chain(data["actor_chain"])

        # Pass 2: baseline scrubbing
        if "baseline_raw" in data:
            data["baseline_raw"] = self._anon_baseline(data["baseline_raw"])

        # Pass 3: tool response scrubbing
        if "connector_tool_calls" in data:
            data["connector_tool_calls"] = [
                self._anon_tool_call(tc) for tc in data["connector_tool_calls"]
            ]

        return data

    # ------------------------------------------------------------------
    # Timestamp offset
    # ------------------------------------------------------------------

    def _build_ts_offset(self) -> None:
        """Derive a deterministic timestamp offset from capture_id."""
        capture_id = self._original.get("capture_id", "")
        digest = int(hashlib.sha256(capture_id.encode()).hexdigest()[:8], 16)
        # Offset in range [1, 365] days
        days = (digest % 365) + 1
        self._ts_offset = timedelta(days=days)

    def _shift_timestamp(self, ts_str: str) -> str:
        """Shift an ISO 8601 timestamp by the capture-level offset."""
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            shifted = dt - self._ts_offset  # type: ignore[operator]
            return shifted.isoformat()
        except (ValueError, TypeError):
            return ts_str

    # ------------------------------------------------------------------
    # Identity map building
    # ------------------------------------------------------------------

    def _prescan(self, data: dict[str, Any]) -> None:
        """Walk the capture in a defined order to assign labels deterministically."""
        # Scan finding_raw, then events_raw (in order), then baseline known_entities
        self._scan_dict_values(data.get("finding_raw", {}))
        for evt in data.get("events_raw", []):
            self._scan_dict_values(evt)
        baseline = data.get("baseline_raw", {})
        for entity in baseline.get("known_entities", []):
            if isinstance(entity, str):
                self._get_user_label(entity)
        for actor in (baseline.get("actor_frequency") or {}).keys():
            self._get_user_label(actor)
        for tc in data.get("connector_tool_calls", []):
            self._scan_dict_values(tc.get("response_raw", {}))

    def _scan_dict_values(self, d: dict[str, Any]) -> None:
        """Scan all string values in a dict to register identities."""
        for k, v in d.items():
            if isinstance(v, str):
                self._register_value(k, v)
            elif isinstance(v, dict):
                self._scan_dict_values(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        self._scan_dict_values(item)

    def _register_value(self, key: str, value: str) -> None:
        """Register a value in the identity map if it looks like an identity."""
        key_lower = key.lower()
        if "actor" in key_lower or "author" in key_lower or "user" in key_lower or "username" in key_lower:
            self._get_user_label(value)
        elif "org" in key_lower or "organization" in key_lower:
            self._get_org_label(value)
        elif "repo" in key_lower or "repository" in key_lower:
            self._get_repo_label(value)
        elif "ip" in key_lower or "address" in key_lower:
            if _IP_RE.match(value):
                self._get_ip_label(value)

    # ------------------------------------------------------------------
    # Label allocation
    # ------------------------------------------------------------------

    def _get_user_label(self, value: str) -> str:
        if value not in self.identity_map:
            label = _USER_LABELS[self._user_counter % len(_USER_LABELS)]
            self._user_counter += 1
            self.identity_map[value] = label
        return self.identity_map[value]

    def _get_org_label(self, value: str) -> str:
        if value not in self.identity_map:
            label = _ORG_LABELS[self._org_counter % len(_ORG_LABELS)]
            self._org_counter += 1
            self.identity_map[value] = label
        return self.identity_map[value]

    def _get_repo_label(self, value: str) -> str:
        if value not in self.identity_map:
            label = _REPO_LABELS[self._repo_counter % len(_REPO_LABELS)]
            self._repo_counter += 1
            self.identity_map[value] = label
        return self.identity_map[value]

    def _get_ip_label(self, value: str) -> str:
        if value not in self.identity_map:
            label = f"10.0.0.{self._ip_counter + 1}"
            self._ip_counter += 1
            self.identity_map[value] = label
        return self.identity_map[value]

    # ------------------------------------------------------------------
    # Pass 1: field-level replacement
    # ------------------------------------------------------------------

    def _anon_str(self, key: str, value: str) -> str:
        """Anonymize a single string value based on its field key."""
        key_lower = key.lower()

        # Email: always canonical placeholder
        if _EMAIL_RE.fullmatch(value.strip()):
            return "user@example.com"

        # IP address
        if _IP_RE.fullmatch(value.strip()):
            return self._get_ip_label(value)

        # Actor / user / author
        if "actor" in key_lower or "author" in key_lower or "user" in key_lower or "username" in key_lower:
            if value in self.identity_map:
                return self.identity_map[value]
            return self._get_user_label(value)

        # Org
        if "org" in key_lower or "organization" in key_lower:
            if value in self.identity_map:
                return self.identity_map[value]
            return self._get_org_label(value)

        # Repo (may contain org/repo pattern like "org/repo")
        if "repo" in key_lower or "repository" in key_lower:
            if value in self.identity_map:
                return self.identity_map[value]
            return self._get_repo_label(value)

        # Email field
        if "email" in key_lower:
            return "user@example.com"

        # Timestamp field
        if "timestamp" in key_lower or "time" in key_lower or "at" in key_lower:
            return self._shift_timestamp(value)

        return value

    def _anon_dict(self, d: dict[str, Any]) -> dict[str, Any]:
        """Apply Pass 1 anonymization to all values in a dict."""
        result: dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(v, str):
                result[k] = self._anon_str(k, v)
            elif isinstance(v, dict):
                result[k] = self._anon_dict(v)
            elif isinstance(v, list):
                result[k] = self._anon_list(k, v)
            else:
                result[k] = v
        return result

    def _anon_list(self, key: str, lst: list[Any]) -> list[Any]:
        result = []
        for item in lst:
            if isinstance(item, str):
                result.append(self._anon_str(key, item))
            elif isinstance(item, dict):
                result.append(self._anon_dict(item))
            else:
                result.append(item)
        return result

    def _anon_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Anonymize an event dict, handling timestamp shift separately."""
        result = self._anon_dict(event)
        # Ensure timestamp is shifted even if not caught by key heuristic
        if "timestamp" in event and isinstance(event["timestamp"], str):
            result["timestamp"] = self._shift_timestamp(event["timestamp"])
        return result

    def _anon_actor_chain(self, ac: dict[str, Any]) -> dict[str, Any]:
        """Pass 1 on actor_chain — preserve action types and token counts."""
        result = dict(ac)
        # Preserve structured fields; only scrub free-text reason + llm reasoning
        if "chain_reason" in ac and isinstance(ac["chain_reason"], str):
            result["chain_reason"] = self._scrub_text(ac["chain_reason"])
        if "llm_calls" in ac and isinstance(ac["llm_calls"], list):
            scrubbed_calls = []
            for call in ac["llm_calls"]:
                c = dict(call)
                if "reasoning_excerpt" in c and isinstance(c["reasoning_excerpt"], str):
                    c["reasoning_excerpt"] = self._scrub_text(c["reasoning_excerpt"])
                scrubbed_calls.append(c)
            result["llm_calls"] = scrubbed_calls
        return result

    def _scrub_text(self, text: str) -> str:
        """Replace known identity strings that appear in free text."""
        for original, synthetic in self.identity_map.items():
            if original in text:
                text = text.replace(original, synthetic)
        # Replace any IP addresses in text
        def _replace_ip(m: re.Match) -> str:
            ip = m.group(0)
            return self._get_ip_label(ip)
        text = _IP_RE.sub(_replace_ip, text)
        # Replace emails
        text = _EMAIL_RE.sub("user@example.com", text)
        return text

    # ------------------------------------------------------------------
    # Pass 2: Baseline scrubbing
    # ------------------------------------------------------------------

    def _anon_baseline(self, baseline: dict[str, Any]) -> dict[str, Any]:
        result = dict(baseline)
        # known_entities: replace each entity name
        if "known_entities" in baseline and isinstance(baseline["known_entities"], list):
            result["known_entities"] = [
                self.identity_map.get(e, self._get_user_label(e)) if isinstance(e, str) else e
                for e in baseline["known_entities"]
            ]
        # actor_frequency: replace actor names (keys), preserve counts (values)
        if "actor_frequency" in baseline and isinstance(baseline["actor_frequency"], dict):
            new_freq: dict[str, Any] = {}
            for actor, count in baseline["actor_frequency"].items():
                label = self.identity_map.get(actor, self._get_user_label(actor))
                new_freq[label] = count
            result["actor_frequency"] = new_freq
        return result

    # ------------------------------------------------------------------
    # Pass 3: Tool response scrubbing
    # ------------------------------------------------------------------

    _NON_SECURITY_KEYS = {
        "message", "body", "description", "content", "text", "comment",
        "diff", "patch", "raw_body", "commit_message",
    }

    def _anon_tool_call(self, tc: dict[str, Any]) -> dict[str, Any]:
        result = dict(tc)
        if "response_raw" in tc and isinstance(tc["response_raw"], dict):
            result["response_raw"] = self._anon_tool_response(tc["response_raw"])
        return result

    def _anon_tool_response(self, resp: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for k, v in resp.items():
            if isinstance(v, str):
                # First apply identity anonymization
                anon_v = self._anon_str(k, v)
                # Then truncate long non-security fields
                if k.lower() in self._NON_SECURITY_KEYS and len(anon_v) > 200:
                    anon_v = anon_v[:200]
                result[k] = anon_v
            elif isinstance(v, dict):
                result[k] = self._anon_tool_response(v)
            elif isinstance(v, list):
                result[k] = self._anon_list(k, v)
            else:
                result[k] = v
        return result


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def anonymize_capture(capture: dict[str, Any]) -> dict[str, Any]:
    """Return a new anonymized copy of a capture dict.

    The original dict is not mutated.
    """
    return Anonymizer(capture).run()
