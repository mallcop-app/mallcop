# OpenClaw Monitor — Design Document

Bead: mallcop-bkde.1 (design session), mallcop-um7f.2.1 (implementation)

## Problem

OpenClaw is the most popular open-source AI agent framework (247k GitHub stars). Its skill ecosystem (13k+ skills on ClawHub) has become a supply-chain attack surface. In Feb 2026, 824+ malicious skills were discovered distributing infostealers (AMOS, RedLine, Lumma). CVE-2026-25253 (CVSS 8.8) allows full gateway compromise via WebSocket hijack. Mallcop needs to monitor OpenClaw installations the same way it monitors cloud infrastructure.

## Threat Model

### T1: Malicious Skill Installation
- Skills from ClawHub containing obfuscated payloads (base64 shell scripts, password-protected ZIPs)
- Infostealer delivery via ClickFix-style setup instructions in SKILL.md
- Known actor: hightower6eu (314+ malicious skills)
- IOCs: quarantine attribute removal (xattr), encoded payloads, external HTTP downloads in setup steps

### T2: Prompt Injection via Skill Content
- SKILL.md instructions that manipulate the agent's behavior
- Memory poisoning: injected content persists across sessions via OpenClaw's memory system
- soul-evil hook pattern: swap system prompt via config.patch + write tool chain

### T3: Data Exfiltration
- Skills with access to env vars, API keys, browser credentials
- Autonomous data sending via email/API tools
- Credential harvesting from `~/.openclaw/openclaw.json` (stores secrets in plaintext)

### T4: Gateway Compromise (ClawJacked)
- WebSocket hijack from malicious websites to localhost gateway
- No rate limiting on localhost auth, silent device registration
- Ports: 3000, 18789

### T5: Configuration Drift
- Authentication disabled by default
- mDNS broadcast leaking gateway presence on LAN (port 5353, `openclaw-gw.tcp`)
- Guest mode tools accessible without auth
- Workspace skills overriding managed/bundled skills (shadow skills)

### T6: MCP Server Abuse
- Over-privileged MCP tool declarations
- Anomalous MCP destinations (unexpected external endpoints)
- Skills bypassing MCP entirely via direct shell commands

## Connector Design

### Source: `openclaw`

Reads local OpenClaw state — no API calls needed (it's all on disk).

#### Discovery Probes
1. Check `~/.openclaw/` exists
2. Read `~/.openclaw/openclaw.json` for gateway config
3. Enumerate `~/.openclaw/skills/` (managed skills)
4. Find workspace skills dirs from config `skills.load.extraDirs`
5. Check gateway process (ports 3000, 18789)

#### Data Sources (what we poll)

| Source | Path/Method | What we get |
|--------|-------------|-------------|
| Installed skills | `~/.openclaw/skills/*/SKILL.md` | Skill manifests, frontmatter, instructions |
| Workspace skills | `<workspace>/skills/*/SKILL.md` | Local/override skills |
| Gateway config | `~/.openclaw/openclaw.json` | Auth settings, skill entries, secrets |
| Gateway logs | `~/.openclaw/logs/` | WebSocket connections, skill invocations, tool calls |
| MCP config | `~/.openclaw/openclaw.json` → mcp servers | Declared MCP endpoints |
| Process state | `lsof`/`ss` on gateway ports | Active connections, unexpected listeners |

#### Event Types

```yaml
event_types:
  - skill_installed        # New skill appeared in skills dir
  - skill_modified         # SKILL.md content changed
  - skill_removed          # Skill directory deleted
  - config_changed         # openclaw.json modified
  - gateway_connection     # New WebSocket connection to gateway
  - tool_invocation        # Agent invoked a tool
  - mcp_call              # MCP server called
  - auth_attempt          # Gateway authentication attempt
  - secret_access         # Skill accessed env var / API key
```

#### Manifest

```yaml
name: openclaw
description: OpenClaw AI agent — skill integrity, behavior monitoring, gateway security
version: 0.1.0

auth:
  required: []
  optional: []

config:
  openclaw_home: "~/.openclaw"
  workspace_dirs: []          # Additional workspace skill directories
  watch_gateway_logs: true
  watch_skills: true

event_types:
  - skill_installed
  - skill_modified
  - skill_removed
  - config_changed
  - gateway_connection
  - tool_invocation
  - mcp_call
  - auth_attempt
  - secret_access

discovery:
  probes:
    - "OpenClaw home directory (~/.openclaw)"
    - "Installed skills enumeration"
    - "Gateway process detection"
    - "MCP server configuration"

tools:
  - name: openclaw.list-skills
    description: List all installed skills with metadata
    permission: read
  - name: openclaw.read-skill
    description: Read a specific skill's SKILL.md content
    permission: read
  - name: openclaw.check-config
    description: Read OpenClaw gateway configuration (secrets redacted)
    permission: read
  - name: openclaw.gateway-status
    description: Check gateway process, ports, active connections
    permission: read
```

#### Implementation: `src/mallcop/connectors/openclaw/`

```
openclaw/
├── manifest.yaml
├── __init__.py          # OpenClawConnector(ConnectorBase)
├── skills.py            # Skill parsing, SKILL.md frontmatter extraction
├── gateway.py           # Gateway log parsing, process detection
└── tools.py             # Connector-specific tools
```

**OpenClawConnector.poll()** logic:
1. Scan skill directories, hash each SKILL.md → detect new/modified/removed
2. Hash openclaw.json → detect config changes
3. Parse gateway logs since last checkpoint → extract connection/auth/tool events
4. Store checkpoint as {skill_hashes: {}, config_hash: str, log_offset: int}

## Detector Design

### D1: `malicious-skill` — Known Bad Skill Signatures

Static analysis of installed skills against known-malicious patterns.

**Detection rules (declarative YAML):**
```yaml
name: malicious-skill
description: Detects known malicious skill patterns and IOCs
version: 0.1.0
sources: ["openclaw"]
event_types: ["skill_installed", "skill_modified"]
severity_default: critical

rules:
  - name: encoded-payload
    description: Base64 or hex-encoded commands in SKILL.md
    condition: regex_match
    field: metadata.skill_content
    pattern: "(base64 -d|echo.*\\|.*sh|curl.*\\|.*bash|wget.*&&.*chmod)"

  - name: quarantine-bypass
    description: macOS Gatekeeper bypass attempt
    condition: regex_match
    field: metadata.skill_content
    pattern: "xattr\\s+-[rd]"

  - name: external-binary
    description: Downloads and executes external binary
    condition: regex_match
    field: metadata.skill_content
    pattern: "(curl|wget).*\\.(exe|bin|dmg|pkg|sh).*&&.*(chmod|bash|sh|\\./)"

  - name: password-protected-archive
    description: Password-protected archive extraction
    condition: regex_match
    field: metadata.skill_content
    pattern: "(unzip.*-P|7z.*-p|tar.*--passphrase)"

  - name: known-malicious-author
    description: Skills from known malicious publishers
    condition: string_match
    field: metadata.skill_author
    values: ["hightower6eu"]
```

### D2: `openclaw-behavior` — Runtime Behavior Anomalies

Behavioral analysis of agent activity patterns.

**Detection logic (Python, not declarative — needs LLM-style reasoning):**

| Signal | What to detect | Severity |
|--------|---------------|----------|
| Data exfil pattern | Bulk file reads followed by external API calls | high |
| Credential harvesting | Access to browser credential stores, SSH keys, cloud configs | critical |
| Prompt injection | Instructions in tool output that alter agent behavior | high |
| Memory poisoning | Skill writing to agent memory/context that persists | high |
| Privilege escalation | config.patch calls, hook modifications, system prompt swaps | critical |
| Unusual MCP destinations | MCP calls to endpoints not in declared config | warn |
| Off-hours automation | Agent activity during non-configured hours | info |

### D3: `openclaw-config-drift` — Configuration Security

**Detection rules (declarative):**
```yaml
name: openclaw-config-drift
description: Detects insecure OpenClaw configuration
version: 0.1.0
sources: ["openclaw"]
event_types: ["config_changed"]
severity_default: warn

rules:
  - name: auth-disabled
    description: Gateway authentication is disabled
    condition: json_field_equals
    field: metadata.config
    json_path: "$.gateway.auth.enabled"
    value: false
    severity: critical

  - name: plaintext-secrets
    description: API keys stored in plaintext in config
    condition: regex_match
    field: metadata.config_raw
    pattern: "(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36})"
    severity: high

  - name: mdns-enabled
    description: mDNS broadcasting gateway presence on LAN
    condition: json_field_equals
    field: metadata.config
    json_path: "$.gateway.mdns.enabled"
    value: true
    severity: warn

  - name: guest-mode-tools
    description: Dangerous tools accessible in guest mode
    condition: json_field_not_empty
    field: metadata.config
    json_path: "$.gateway.guestMode.tools"
    severity: warn

  - name: shadow-skill-override
    description: Workspace skill overriding a managed/bundled skill
    condition: string_match
    field: metadata.override_type
    values: ["workspace_overrides_managed", "workspace_overrides_bundled"]
    severity: high
```

### D4: `gateway-compromise` — Gateway Security

**Detection rules:**
```yaml
name: gateway-compromise
description: Detects gateway compromise indicators (ClawJacked pattern)
version: 0.1.0
sources: ["openclaw"]
event_types: ["gateway_connection", "auth_attempt"]
severity_default: critical

rules:
  - name: websocket-brute-force
    description: Multiple failed auth attempts from same origin
    condition: count_threshold
    field: metadata.source_origin
    threshold: 10
    window_minutes: 5

  - name: cross-origin-websocket
    description: WebSocket connection from non-localhost origin
    condition: regex_match
    field: metadata.source_origin
    pattern: "^(?!localhost|127\\.0\\.0\\.1|\\[::1\\])"

  - name: silent-device-registration
    description: New device registered without user prompt
    condition: string_match
    field: event_type
    values: ["device_auto_registered"]
```

## Implementation Plan (Bead Tree)

The parent bead mallcop-um7f.2.1 covers all implementation. Sub-tasks:

1. **Connector skeleton**: `connectors/openclaw/` with manifest, discover, authenticate, poll
2. **Skill parser**: SKILL.md frontmatter extraction, content hashing, diff detection
3. **Gateway monitor**: Log parsing, process detection, connection tracking
4. **Declarative detectors**: malicious-skill, openclaw-config-drift, gateway-compromise (YAML rules)
5. **Behavioral detector**: openclaw-behavior (Python, runtime pattern matching)
6. **Connector tools**: list-skills, read-skill, check-config, gateway-status
7. **Fixtures**: Recorded skill manifests, config snapshots, gateway logs for each attack vector
8. **Tests**: Unit (parser, each detector rule), integration (poll → detect pipeline), functional (scan + detect flags known attacks)

## Fixture Strategy

Since OpenClaw is local (filesystem, not API), fixtures are directory snapshots:

```
tests/fixtures/openclaw/
├── clean_install/           # Healthy OpenClaw installation
│   ├── openclaw.json
│   └── skills/
│       ├── web-search/SKILL.md
│       └── calendar/SKILL.md
├── malicious_skill/         # hightower6eu-style attack
│   ├── openclaw.json
│   └── skills/
│       └── solana-tracker/SKILL.md  # Contains encoded payload
├── config_drift/            # Insecure configuration
│   └── openclaw.json        # Auth disabled, mDNS on, plaintext keys
├── gateway_attack/          # ClawJacked scenario
│   └── gateway.log          # Brute-force auth + silent device registration
└── prompt_injection/        # Memory poisoning via skill
    └── skills/
        └── helpful-tool/SKILL.md   # Contains injection in instructions
```

## False Positive Mitigation

- **Encoded payloads**: Many legitimate skills use base64 for config. Check context: is it piped to `sh`/`bash`? Is it a data blob or an execution chain?
- **External downloads**: Legitimate skills install binaries (e.g., `clawhub install`). Flag only download+execute patterns, not downloads alone.
- **Config secrets**: Some users intentionally store keys in config. Warn severity, not critical. The finding should say "consider using env vars instead."
- **Shadow skills**: Developers override skills for local development. Flag as info when in a known dev workspace, warn otherwise.

## Open Questions

1. **Gateway log format**: Need to confirm exact log format and location. May vary by version. The connector should auto-detect from config.
2. **MCP server enumeration**: How does OpenClaw declare MCP servers in config? Need to map `openclaw.json` → MCP entries.
3. **Skill verification**: ClawHub added VirusTotal scanning. Should mallcop check VT hashes too, or is local analysis sufficient for v1?

## Decision: v1 Scope

For v1 (this release), implement:
- Connector with skill scanning and config monitoring (no gateway log parsing yet — log format needs live validation)
- malicious-skill detector (static SKILL.md analysis)
- openclaw-config-drift detector (config security)
- Fixtures for each attack vector
- Full test coverage

Defer to v1.1:
- Gateway log parsing (needs live OpenClaw instance to validate format)
- gateway-compromise detector (depends on log parsing)
- openclaw-behavior detector (runtime analysis needs MCP integration)
- VT hash checking
