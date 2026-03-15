"""Local CLI telemetry. Opt-in only. Nothing is shipped without consent.

Enable:  mkdir -p ~/.mallcop && touch ~/.mallcop/telemetry-enabled
Disable: rm ~/.mallcop/telemetry-enabled
"""
from __future__ import annotations

import functools
import json
import time
from datetime import datetime, timezone
from pathlib import Path

_MALLCOP_DIR = Path.home() / ".mallcop"
_ENABLED_FLAG = _MALLCOP_DIR / "telemetry-enabled"
_LOG_FILE = _MALLCOP_DIR / "telemetry.jsonl"


def is_enabled() -> bool:
    return _ENABLED_FLAG.exists()


def _log_invocation(
    command: str,
    flags: list[str],
    exit_code: int,
    wall_time_ms: float,
    log_file: Path | None = None,
) -> None:
    """Append one invocation record to the telemetry log."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "flags": flags,
        "exit_code": exit_code,
        "wall_time_ms": round(wall_time_ms, 1),
    }
    dest = log_file or _LOG_FILE
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError:
        pass  # telemetry is best-effort


def log_cli(fn=None):
    """Click command decorator that logs invocation shape when telemetry is enabled."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not is_enabled():
                return func(*args, **kwargs)

            import click
            ctx = click.get_current_context(silent=True)
            cmd_name = ctx.info_name if ctx else func.__name__
            flags = [k for k, v in (kwargs or {}).items() if v is not None and v is not False]

            t0 = time.monotonic()
            exit_code = 0
            try:
                result = func(*args, **kwargs)
                return result
            except SystemExit as e:
                exit_code = e.code if isinstance(e.code, int) else 1
                raise
            except Exception:
                exit_code = 1
                raise
            finally:
                wall_ms = (time.monotonic() - t0) * 1000
                _log_invocation(cmd_name, flags, exit_code, wall_ms)

        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator
