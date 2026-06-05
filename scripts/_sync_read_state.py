#!/usr/bin/env python3
"""Read the live capabilities-campfire state by walking message CBOR files.

Bypasses `cf read` (which can't read legion-managed campfires due to the
identity-mismatch noted in legion-cd41 — cf and legion use separate
identity files: $CF_HOME/identity.json vs $CF_HOME/campfire-identity/).

Output: JSON to stdout, shape:
  {
    "<capability-name>": {
      "active": {                 # latest active future (highest ts wins)
        "msg_id": "...",
        "payload": {...},         # parsed JSON payload
        "canonical": "...",       # canonical JSON for diff
        "fulfilled_by": "..."     # fulfillment msg-id or null
      },
      "pending": {                # propose without active fulfillment
        "msg_id": "...",
        "payload": {...},
        "canonical": "..."
      }
    },
    ...
  }

Usage:
  _sync_read_state.py <transport-dir> <capabilities-cf-id>
"""
import json
import os
import sys
from pathlib import Path

try:
    import cbor2
except ImportError:
    print("error: cbor2 not installed. Install via pip in a venv.", file=sys.stderr)
    sys.exit(2)


def canonical_json(obj):
    """Stable JSON: sorted keys, compact separators, no whitespace drift."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def read_messages(cap_dir):
    msgs = []
    msg_root = Path(cap_dir) / "messages"
    if not msg_root.is_dir():
        return msgs
    for path in msg_root.rglob("*.cbor"):
        try:
            with open(path, "rb") as f:
                m = cbor2.load(f)
        except Exception as e:
            print(f"warn: parse {path}: {e}", file=sys.stderr)
            continue
        if not isinstance(m, dict):
            continue
        # CBOR int-key schema: 1=id, 2=sender, 3=payload(bytes), 4=tags,
        # 5=antecedents, 6=timestamp, 7=signature, 8=provenance
        msg_id = m.get(1) or ""
        payload_bytes = m.get(3) or b""
        tags = m.get(4) or []
        antecedents = m.get(5) or []
        ts = m.get(6) or 0
        payload_str = (
            payload_bytes.decode("utf-8", errors="replace")
            if isinstance(payload_bytes, (bytes, bytearray))
            else str(payload_bytes)
        )
        msgs.append(
            {
                "id": msg_id,
                "tags": list(tags),
                "antecedents": list(antecedents),
                "timestamp": ts,
                "payload": payload_str,
            }
        )
    msgs.sort(key=lambda m: m["timestamp"])
    return msgs


def compute_state(messages):
    """Group by capability name. Return {name: {active|pending: ...}}.

    Algorithm:
      - A FUTURE message has tags [future, capability].
      - A FULFILLMENT has tags [fulfills, capability-active|capability-revoked]
        and its antecedents reference the future's msg-id.
      - A SUPERSEDE chain is FUTURE messages with tags containing
        "capability-supersedes" plus the old future-id in antecedents.

    For each capability name (from payload.name):
      - The LATEST future (highest ts) wins.
      - "active" = latest future with the most recent fulfillment tagged
        capability-active; ignore those whose latest fulfillment is
        capability-revoked.
      - "pending" = latest future with NO fulfillment at all yet.
    """
    futures = {}  # msg_id -> {ts, payload, name}
    fulfill_for = {}  # future_id -> [(ts, decision), ...]

    for m in messages:
        tags = m["tags"]
        if "future" in tags and "capability" in tags:
            try:
                p = json.loads(m["payload"]) if m["payload"] else None
            except Exception:
                continue
            if not isinstance(p, dict) or not p.get("name"):
                continue
            futures[m["id"]] = {
                "ts": m["timestamp"],
                "payload": p,
                "name": p["name"],
            }
        elif "fulfills" in tags:
            decision = None
            if "capability-active" in tags:
                decision = "active"
            elif "capability-revoked" in tags:
                decision = "revoked"
            if not decision:
                continue
            for ant in m["antecedents"]:
                fulfill_for.setdefault(ant, []).append((m["timestamp"], decision))

    # Group futures by capability name, keep latest-ts.
    by_name_active = {}  # name -> latest future-record with fulfillment=active
    by_name_pending = {}  # name -> latest future-record with no fulfillment

    for msg_id, fut in futures.items():
        fulfillments = sorted(fulfill_for.get(msg_id, []), key=lambda x: x[0])
        latest_decision = fulfillments[-1][1] if fulfillments else None
        if latest_decision == "active":
            cur = by_name_active.get(fut["name"])
            if cur is None or fut["ts"] > cur["ts"]:
                by_name_active[fut["name"]] = {
                    "msg_id": msg_id,
                    "ts": fut["ts"],
                    "payload": fut["payload"],
                    "canonical": canonical_json(fut["payload"]),
                    "fulfilled_by_decision": "active",
                }
        elif latest_decision is None:
            cur = by_name_pending.get(fut["name"])
            if cur is None or fut["ts"] > cur["ts"]:
                by_name_pending[fut["name"]] = {
                    "msg_id": msg_id,
                    "ts": fut["ts"],
                    "payload": fut["payload"],
                    "canonical": canonical_json(fut["payload"]),
                }

    out = {}
    for name in set(list(by_name_active) + list(by_name_pending)):
        entry = {}
        if name in by_name_active:
            entry["active"] = by_name_active[name]
        if name in by_name_pending:
            entry["pending"] = by_name_pending[name]
        out[name] = entry
    return out


def main():
    if len(sys.argv) != 3:
        print(
            "usage: _sync_read_state.py <transport-dir> <capabilities-cf-id>",
            file=sys.stderr,
        )
        sys.exit(2)
    transport, cap_id = sys.argv[1], sys.argv[2]
    cap_dir = os.path.join(transport, cap_id)
    if not os.path.isdir(cap_dir):
        # Empty state — first init.
        print("{}")
        return
    msgs = read_messages(cap_dir)
    state = compute_state(msgs)
    print(json.dumps(state, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
