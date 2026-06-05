#!/usr/bin/env bash
# Extract one [[capabilities.seed]] block (by name) from the chart template
# and emit its body as a standalone single-capability TOML.
#
# Strip the leading `[[capabilities.seed]]` line and dedent the
# `[[capabilities.seed.tool_defs]]` subblock headers to `[[tool_defs]]`.
# The output conforms to legion's capabilityPayloadTOML struct (see
# cmd/we/capability_cmd.go) and is what `we capability propose --file`
# expects.
#
# Usage:
#   extract-seed-block.sh <chart-tmpl-path> <capability-name>
#
# Example:
#   extract-seed-block.sh charts/mallcop-operational.toml.tmpl triage
set -euo pipefail

CHART="${1:?usage: extract-seed-block.sh <chart-tmpl> <name>}"
NAME="${2:?usage: extract-seed-block.sh <chart-tmpl> <name>}"

python3 - "$CHART" "$NAME" <<'PYEOF'
import re
import sys

chart_path, target_name = sys.argv[1], sys.argv[2]
text = open(chart_path).read()

# Split on top-level [[capabilities.seed]] (NOT [[capabilities.seed.tool_defs]]).
# Lookbehind: line-start. Lookahead: must be the bare double-bracket form.
pattern = re.compile(r"^\[\[capabilities\.seed\]\]\s*$", re.MULTILINE)
matches = list(pattern.finditer(text))
if not matches:
    sys.exit(f"no [[capabilities.seed]] blocks found in {chart_path}")

# Find next top-level section header (starts with `[` at column 0, not `[[capabilities.seed.tool_defs]]`).
boundary_pat = re.compile(r"^\[[^[]", re.MULTILINE)

for i, m in enumerate(matches):
    start = m.end()  # exclusive of the [[capabilities.seed]] line
    # End: next [[capabilities.seed]] OR next top-level section.
    next_seed = matches[i+1].start() if i+1 < len(matches) else None
    next_boundary = None
    for b in boundary_pat.finditer(text, start):
        next_boundary = b.start()
        break
    end_candidates = [c for c in (next_seed, next_boundary) if c is not None]
    end = min(end_candidates) if end_candidates else len(text)

    block_body = text[start:end].rstrip() + "\n"

    # Find name= line in this block to identify it.
    name_match = re.search(r'^\s*name\s*=\s*"([^"]+)"', block_body, re.MULTILINE)
    if not name_match:
        continue
    if name_match.group(1) != target_name:
        continue

    # Found the block. Transformations:
    #   1) Drop [capabilities.seed.behaviors.*] subblocks entirely. They
    #      are dead chart-side config — nothing in legion reads them
    #      (verified 2026-06-05, mallcoppro-83a). Including them would
    #      cause `we capability propose --file` to reject the TOML with
    #      "unknown fields".
    #   2) Drop top-level `max_iters` lines. Same situation — chart sets
    #      max_iters per-skill (triage=3, investigate=10, etc) but
    #      legion's capabilityPayloadTOML schema has no MaxIters field
    #      and grep finds no consumer in legion source. Per-capability
    #      iteration capping comes from the tool_loop turn cap.
    #   3) Dedent [[capabilities.seed.tool_defs]] → [[tool_defs]] and the
    #      fields beneath it so the standalone TOML is flush-left.
    out_lines = []
    in_tool_def = False
    in_dead_behaviors = False
    for line in block_body.splitlines():
        stripped = line.strip()

        # Drop dead top-level `max_iters` lines.
        if re.match(r"^\s*max_iters\s*=", line) and not in_tool_def:
            continue

        # Detect entry/exit of dead behaviors subblock.
        if re.match(r"^\s*\[capabilities\.seed\.behaviors", line):
            in_dead_behaviors = True
            in_tool_def = False
            continue
        # Detect leaving the dead block: another subsection header (e.g. tool_defs).
        if in_dead_behaviors and re.match(r"^\s*\[", line):
            in_dead_behaviors = False
            # fall through to handle this line
        if in_dead_behaviors:
            # Drop the field/comment line inside the dead block.
            continue

        # Dedent tool_defs subblock header.
        if re.match(r"^\s*\[\[capabilities\.seed\.tool_defs\]\]\s*$", line):
            in_tool_def = True
            out_lines.append("[[tool_defs]]")
            continue
        if in_tool_def and line.startswith("  ") and "=" in line:
            out_lines.append(line[2:])
            continue
        if in_tool_def and stripped.startswith("#"):
            out_lines.append(line[2:] if line.startswith("  ") else line)
            continue
        # Top-level fields outside any subblock.
        out_lines.append(line)

    sys.stdout.write("\n".join(out_lines).rstrip() + "\n")
    sys.exit(0)

sys.exit(f"capability {target_name!r} not found in {chart_path}")
PYEOF
