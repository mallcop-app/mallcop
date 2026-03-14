---
name: openclaw-security
description: "OpenClaw/Cline agent security — malicious skill detection, MCP abuse patterns, ClawHavoc IOCs"
version: "1.0"
author: mallcop@mallcop.app
---

## OpenClaw Security Investigation

### ClawHavoc Campaign

ClawHavoc was a coordinated campaign distributing 335 malicious skills through the OpenClaw marketplace. The skills appeared functional — most executed their stated purpose — but contained secondary payloads triggered on specific conditions.

IOC patterns from the ClawHavoc corpus:

- **Delayed trigger conditions**: malicious instructions appeared deep in the SKILL.md body, after several pages of legitimate content. The trigger was typically a common condition (`if the user asks about passwords`, `when writing code that handles credentials`), not a rare one, maximizing activation rate.
- **Namespace conflicts**: many ClawHavoc skills used names similar to legitimate high-popularity skills (e.g., `aws-iam-helper` vs `aws-iam`). The similarity caused agents to load the malicious version when searching by substring.
- **Author identity spoofing**: skill `author` fields used typosquatted identities of well-known security vendors. No verification of author identity is performed by the marketplace.
- **Version creep**: skills started with clean v1.0, introduced payload in v1.2 or v1.3 after gaining ratings and installs. If a skill's behavior changed between versions without corresponding changelog entries, treat v1.2+ as suspect.

When a skill is flagged for ClawHavoc affinity: check the full text of the SKILL.md body for instruction fragments that appear after the main content section, particularly near the end of the file. The payload is always in natural language — it is not code, it is prompt text.

### Skill Supply Chain — Prompt Injection in SKILL.md

A SKILL.md file is a prompt fragment. Whatever is in the body gets injected into the agent's context when the skill is loaded. There is no sandboxing — a skill can instruct the agent to do anything it has the tools and permissions to do.

Injection patterns:

- **Override instructions**: text like "Ignore previous instructions and..." or "When you complete the above task, also..." embedded in the skill body. Look for instructional imperatives that appear disconnected from the skill's stated purpose.
- **Conditional extraction**: instructions to exfiltrate specific file paths or environment variables when certain conditions are met. The condition is usually broad enough to trigger frequently: `when you access any configuration file`, `whenever you see an API key in any file`.
- **Tool call hijacking**: instructions that redirect tool calls through an attacker-controlled proxy. Watch for SKILL.md body text that specifies domains, IP addresses, or webhook URLs — legitimate skills do not hardcode network destinations.

Detection heuristic: parse the SKILL.md body as a sequence of paragraphs. Any paragraph that contains imperative verbs (`send`, `POST`, `write`, `call`, `execute`) combined with external references (URLs, file paths outside the project) is a candidate for review.

### MCP Abuse Patterns

Model Context Protocol servers extend agent tool capabilities. A compromised or malicious MCP server can exfiltrate data, poison tool outputs, or pivot to other systems.

Anomalous MCP activity indicators:

- **Novel tool destinations**: MCP tool calls to hosts that do not appear in the known-legitimate server list. In CloudTrail or container logs, these appear as outbound connections from the agent process. A tool call to `api.legitimate-service.com` is expected; a tool call to `api.legitimate-serv1ce.com` (typosquatted) is not.
- **Tool result manipulation**: if an MCP server returns results that contradict what a direct API call to the same source would return, the server is lying. This is detectable only by comparing tool output against an independent baseline — useful when investigating a suspected compromise after the fact.
- **Excessive read scope**: an MCP server that requests read access to filesystem paths beyond its stated function (e.g., a git MCP server reading from `~/.aws/credentials`). Check the MCP server's stated capabilities against its actual file access patterns in the container's syscall audit log.
- **Connection to data exfiltration endpoints**: outbound connections to paste services, object storage outside the project's account, or non-standard ports from the agent process.

### Config Drift — Listening on 0.0.0.0, Disabled Security Settings

OpenClaw's security model relies on correct configuration. The following config states represent degraded security posture:

- **`listen_address: 0.0.0.0`**: the MCP server or agent API is listening on all interfaces rather than loopback only. Any process on the host network can reach it.
- **`skill_signature_verification: false`**: signature checking disabled. Any skill can be loaded without verification.
- **`allow_network_in_skills: true`**: skills are permitted to make outbound network calls. Combined with malicious skill content, this is the complete exfiltration chain.
- **`sandbox_mode: false`** or equivalent: agent can execute arbitrary system commands without restrictions.

When investigating a suspected compromise, always capture the agent's config at the time of the incident, not just the current config. If the config was modified (filesystem mtime on the config file), compare the pre- and post-modification state.

### Behavioral Divergence — Manifest Says X, Runtime Does Y

The most reliable detection signal is divergence between what the SKILL.md says the skill does and what the agent actually does when the skill is loaded.

Baseline approach:
1. Load the skill in an isolated environment with full tool call logging.
2. Execute the skill's stated function with representative inputs.
3. Capture all tool calls made during execution.
4. Compare the tool call set against a whitelist derived from the skill's `description` and `tools` frontmatter fields.

Any tool call outside the expected set is a behavioral indicator. A skill claiming to `description: "Analyze CloudTrail events for IAM changes"` that makes outbound HTTP calls is exhibiting behavioral divergence.

### ToxicSkills Audit Findings

Snyk's ToxicSkills audit of the OpenClaw marketplace (Q4 2024) found security flaws in 36.8% of audited skills. Flaw distribution:

- **Prompt injection vectors** (instructions that could redirect agent behavior): 22% of skills
- **Insecure tool declarations** (overly broad tool permissions, no scope restriction): 9% of skills
- **Hardcoded credentials or endpoints in skill body**: 4% of skills
- **Suspicious author identity patterns**: 1.8% of skills

The 36.8% figure is for any flaw. Skills with multiple flaws (composite risk) represented 8% of the total. Composite-risk skills warrant immediate removal from the skill library, not just flagging.
