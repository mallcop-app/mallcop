#!/usr/bin/env python3
"""Read each TOML in --tomls-dir, render canonical JSON of the payload that
`we capability propose --file` would post for it.

Output: JSON to stdout, shape:
  {
    "<name>": {
      "toml_path": "...",
      "payload": {...},
      "canonical": "..."
    },
    ...
  }

This must match the JSON shape legion's capabilityPayloadTOML →
automaton.CapabilityPayload emits.  Cross-referenced against fields in
cmd/we/capability_cmd.go's `capabilityPayloadTOML` struct.

Usage:
  _sync_desired_state.py <tomls-dir>
"""
import json
import os
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    print("error: tomllib (Python 3.11+) required", file=sys.stderr)
    sys.exit(2)


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def toml_to_payload(toml_data):
    """Convert raw TOML dict → the same shape legion's
    capabilityPayloadTOML.toCapabilityPayload() emits, so canonical JSON
    is comparable to what comes off the campfire.
    """
    payload = {
        "name": toml_data.get("name", ""),
        "match": toml_data.get("match", []),
        "tools": toml_data.get("tools", []),
        "template": toml_data.get("template", ""),
        "model": toml_data.get("model", ""),
        "ttl": int(toml_data.get("ttl", 0)),
        "scope": toml_data.get("scope") or None,
        "params": toml_data.get("params") or None,
    }
    # `match` can be a string in TOML; legion normalizes to a list.
    if isinstance(payload["match"], str):
        payload["match"] = [payload["match"]]
    # tool_defs: list of objects, each with name/description/input_schema/binary/binary_args
    tool_defs_raw = toml_data.get("tool_defs", [])
    tool_defs = []
    for td in tool_defs_raw:
        if not isinstance(td, dict):
            continue
        td_out = {
            "name": td.get("name", ""),
            "description": td.get("description", ""),
            "binary": td.get("binary", ""),
            "binary_args": td.get("binary_args", []) or None,
        }
        # legion's input_schema is json.RawMessage in JSON-land — represented
        # as a parsed JSON object on the wire.
        is_str = td.get("input_schema", "")
        if is_str:
            try:
                td_out["input_schema"] = json.loads(is_str)
            except json.JSONDecodeError:
                td_out["input_schema"] = is_str
        else:
            td_out["input_schema"] = None
        tool_defs.append(td_out)
    payload["tool_defs"] = tool_defs or None

    # Legion's JSON wire format includes some fields even when they hold
    # zero values (verified by comparing to live campfire payloads):
    #   - scope: null (kept)
    #   - template: "" (kept)
    #   - ttl: 0 (kept)
    # Other empty fields ARE dropped:
    #   - params, tool_defs if None
    # We mirror this exactly so canonical JSON matches the live wire form.
    out = {}
    KEEP_EMPTY = {"scope", "template", "ttl"}
    for k, v in payload.items():
        if k in KEEP_EMPTY:
            out[k] = v
            continue
        if v in (None, "", [], {}):
            continue
        out[k] = v
    return out


def main():
    if len(sys.argv) != 2:
        print("usage: _sync_desired_state.py <tomls-dir>", file=sys.stderr)
        sys.exit(2)
    tomls_dir = sys.argv[1]
    out = {}
    for p in sorted(Path(tomls_dir).glob("*.toml")):
        with open(p, "rb") as f:
            data = tomllib.load(f)
        payload = toml_to_payload(data)
        name = payload.get("name")
        if not name:
            continue
        out[name] = {
            "toml_path": str(p),
            "payload": payload,
            "canonical": canonical_json(payload),
        }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
