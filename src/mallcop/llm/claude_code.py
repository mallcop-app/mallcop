"""Claude Code CLI client."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall

_log = logging.getLogger(__name__)

_ENV_WHITELIST = frozenset({
    "PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL",
    "TMPDIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
    "ANTHROPIC_API_KEY",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION",
    "GITHUB_TOKEN",
    "M365_CLIENT_ID", "M365_CLIENT_SECRET", "M365_TENANT_ID",
    "VERCEL_TOKEN",
    "OPENAI_API_KEY",
})

_CLAUDE_CODE_TOOL_PROMPT = """\
You have access to the following tools. To call a tool, respond with ONLY a JSON object:
{{"action": "tool_call", "tool_calls": [{{"name": "<tool_name>", "arguments": {{...}}}}]}}

To provide a final resolution (when you have enough information), respond with ONLY:
{{"action": "resolution", "finding_id": "<id>", "action": "<resolved|escalated>", "reason": "<explanation>"}}

Available tools:
{tool_descriptions}

IMPORTANT: Respond with ONLY the JSON object, no other text."""


class ClaudeCodeClient(LLMClient):
    """LLM client that shells out to the claude CLI."""

    def __init__(self, model: str = "sonnet", claude_bin: str | None = None) -> None:
        self._model = model
        self._claude_bin = claude_bin or shutil.which("claude") or "claude"

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        tool_desc_parts = []
        for t in tools:
            params = t.get("parameters", {})
            tool_desc_parts.append(
                f"- {t['name']}: {t.get('description', '')}\n"
                f"  Parameters: {json.dumps(params)}"
            )
        tool_descriptions = "\n".join(tool_desc_parts) if tool_desc_parts else "(none)"

        prompt_parts = [
            _CLAUDE_CODE_TOOL_PROMPT.format(tool_descriptions=tool_descriptions),
            "",
            "=== CONVERSATION ===",
        ]
        for msg in messages:
            role = msg["role"]
            if role == "tool":
                prompt_parts.append(f"[Tool result from {msg.get('name', '?')}]:")
                prompt_parts.append(str(msg.get("content", "")))
            elif role == "assistant":
                prompt_parts.append(f"[Assistant]: {msg.get('content', '')}")
            elif role == "user":
                prompt_parts.append(f"[User]: {msg.get('content', '')}")
        prompt_parts.append("")
        prompt_parts.append("Respond with ONLY a JSON object (tool_call or resolution):")

        full_prompt = "\n".join(prompt_parts)

        # Write prompt to a temp file and pass via stdin to avoid arg-length issues
        prompt_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
        )
        prompt_file.write(full_prompt)
        prompt_file.close()
        prompt_path = prompt_file.name

        cmd = [
            self._claude_bin,
            "-p", "-",
            "--output-format", "text",
            "--model", self._model,
            "--dangerously-skip-permissions",
            "--no-session-persistence",
            "--setting-sources", "",
        ]
        if system_prompt:
            cmd.extend(["--append-system-prompt", system_prompt])

        # Claude Code kills child `claude` processes in its process tree.
        # systemd-run --user launches in a separate cgroup, invisible to parent.
        if os.environ.get("CLAUDECODE") == "1":
            cmd = ["systemd-run", "--user", "--collect", "--pipe", "--quiet"] + cmd

        env = {k: v for k, v in os.environ.items() if k in _ENV_WHITELIST}

        _log.debug("Invoking claude CLI: %s", " ".join(cmd[:4]))

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with open(prompt_path) as in_f, open(tmp_path, "w") as out_f:
                result = subprocess.run(cmd, stdin=in_f, stdout=out_f, stderr=subprocess.PIPE, env=env, timeout=300)
        except subprocess.TimeoutExpired:
            raise LLMAPIError("Claude CLI timed out after 300 seconds")
        except KeyboardInterrupt:
            raise

        try:
            with open(tmp_path) as f:
                output = f.read().strip()
        finally:
            os.unlink(tmp_path)
            os.unlink(prompt_path)

        rc = result.returncode
        if rc != 0:
            stderr_text = result.stderr.decode("utf-8", errors="replace")[:500] if result.stderr else ""
            raise LLMAPIError(f"Claude CLI exited with code {rc}: {stderr_text}")

        if not output:
            raise LLMAPIError("Claude CLI returned empty output")

        _log.debug("Claude CLI response: %s", output[:200])

        return self._parse_response(output)

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        """Extract a top-level JSON object from text, handling nested braces."""
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            pass

        i = 0
        while i < len(text):
            if text[i] == "{":
                decoder = json.JSONDecoder()
                try:
                    obj, end_idx = decoder.raw_decode(text, i)
                    if isinstance(obj, dict):
                        return obj
                except (json.JSONDecodeError, ValueError):
                    pass
            i += 1

        return None

    def _parse_response(self, text: str) -> LLMResponse:
        """Parse claude CLI text output into an LLMResponse."""
        obj = self._extract_json(text)

        if obj is None:
            _log.warning("Could not parse JSON from claude CLI output: %s", text[:200])
            return LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=0,
                raw_resolution=None,
                text=text,
            )

        action = obj.get("action", "")

        if action in ("tool_call", "tool_calls"):
            tool_calls = []
            for tc in obj.get("tool_calls", []):
                tool_calls.append(ToolCall(
                    name=tc["name"],
                    arguments=tc.get("arguments", {}),
                ))
            return LLMResponse(
                tool_calls=tool_calls,
                resolution=None,
                tokens_used=0,
                raw_resolution=None,
                text=text,
            )

        if action == "resolution":
            return LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=0,
                raw_resolution=obj,
                text=text,
            )

        if "finding_id" in obj and "action" in obj:
            return LLMResponse(
                tool_calls=[],
                resolution=None,
                tokens_used=0,
                raw_resolution=obj,
                text=text,
            )

        # Unknown format — pass through as text (e.g., judge responses)
        _log.debug("Non-standard response format from claude CLI: %s", text[:200])
        return LLMResponse(
            tool_calls=[],
            resolution=None,
            tokens_used=0,
            raw_resolution=None,
            text=text,
        )
