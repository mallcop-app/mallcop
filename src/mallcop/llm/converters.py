"""Shared LLM message/tool conversion helpers."""

from __future__ import annotations

import json
from typing import Any

# Single source of truth for the default max_tokens across all LLM providers.
DEFAULT_MAX_TOKENS: int = 4096


def _python_type_to_json(ptype: str) -> str:
    """Map Python type names to JSON Schema type strings."""
    mapping = {
        "str": "string",
        "int": "integer",
        "float": "number",
        "bool": "boolean",
        "list": "array",
        "dict": "object",
        "None": "null",
        "NoneType": "null",
    }
    return mapping.get(ptype, "string")


def _normalize_tool_schema(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a tool parameter schema into valid JSON Schema."""
    if "type" in raw and raw["type"] == "object":
        return raw
    properties: dict[str, Any] = {}
    required: list[str] = []
    for pname, pinfo in raw.items():
        prop: dict[str, Any] = {}
        if isinstance(pinfo, dict):
            ptype = pinfo.get("type", "string")
            prop["type"] = _python_type_to_json(ptype)
            if pinfo.get("description"):
                prop["description"] = pinfo["description"]
            if pinfo.get("required", False):
                required.append(pname)
        else:
            prop["type"] = "string"
        properties[pname] = prop
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _extract_resolution(text: str) -> dict[str, Any] | None:
    """Try to extract a resolution JSON object from text content.

    Tries each complete {...} span in left-to-right order rather than using
    rfind('}'), which would span across multiple JSON objects and produce
    invalid JSON.  A length cap (64 KB) guards against pathologically large
    inputs.
    """
    MAX_LEN = 65536
    text = text.strip()[:MAX_LEN]

    # Fast path: the whole text is valid JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "finding_id" in obj and "action" in obj:
            return obj
    except (json.JSONDecodeError, ValueError):
        pass

    # Scan for each '{' and try to find the matching '}' via a bracket counter,
    # then attempt json.loads on that span.  This avoids rfind picking the
    # outermost '}' across multiple JSON objects.
    i = 0
    while i < len(text):
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[i : j + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict) and "finding_id" in obj and "action" in obj:
                            return obj
                    except (json.JSONDecodeError, ValueError):
                        pass
                    break
            j += 1
        i += 1

    return None
