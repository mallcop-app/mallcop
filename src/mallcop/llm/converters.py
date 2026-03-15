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
    """Try to extract a resolution JSON object from text content."""
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "finding_id" in obj and "action" in obj:
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            if isinstance(obj, dict) and "finding_id" in obj and "action" in obj:
                return obj
        except (json.JSONDecodeError, ValueError):
            pass
    return None
