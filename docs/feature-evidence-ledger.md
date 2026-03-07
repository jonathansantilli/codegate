# CodeGate Feature Evidence Ledger

Last updated: 2026-03-07

## Purpose

This document tracks which CodeGate feature families are worth carrying forward, how complete they are in the current product, what public evidence supports them, and whether we have already validated them against temp-only real-world samples.

Scale used in this ledger:

- **Evidence strength**
  - `Strong`: direct public incidents, advisories, or live marketplace samples
  - `Moderate`: strong analog evidence or official guidance, but limited direct public artifacts
  - `Weak`: mostly preventive/product-hardening value, limited public incident evidence
- **Status**
  - `Mature`: shipped and validated on real or representative cases
  - `Implemented`: shipped, but real-world validation is still limited
  - `Partial`: some behavior exists, but coverage or confidence is incomplete

## Feature Families

| Feature family | What CodeGate does | Status | Evidence strength | Public evidence | Real temp-only validation | Recommendation |
|---|---|---:|---:|---|---|---|
| Cross-tool config discovery | Finds project and user-scope config/instruction/plugin surfaces across Claude, Codex, Cursor, Windsurf, Kiro, Cline, Roo, Zed, Gemini CLI, Copilot, and Junie. | Implemented | Moderate | Supported by the attack surfaces described in [Claude Code project-file research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/), [Codex CLI project-local config RCE](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/), [Cursor MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/), and [AWS Kiro / Amazon Q bulletin](https://aws.amazon.com/security/security-bulletins/AWS-2025-019/). | Indirectly validated by scanning real samples from public skill repos. | Keep |
| Environment override detection | Flags hostile endpoint/base-URL and env redirection settings in project/user configs. | Mature | Strong | [Check Point on Claude Code `ANTHROPIC_BASE_URL` exfiltration](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) directly justifies this family. | Supported by existing fixtures; no new public temp sample rerun needed. | Keep |
| Command-surface detection | Flags executable commands in MCP configs, hooks, workflows, object templates, and markdown execute blocks. | Mature | Strong | [Codex CLI command injection](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/), [Claude Code project-file RCE](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/), and [AWS-2025-019](https://aws.amazon.com/security/security-bulletins/AWS-2025-019/) all depend on committed command surfaces. | Validated on live `security-review` and `frankenphp` skill files. | Keep |
| Consent-bypass / auto-approval detection | Flags `alwaysAllow`, `autoApprove`, `yolo`, enterprise bypass flags, and remote-MCP policies that suppress review or HITL. | Mature | Strong | [Cursor MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) and [AWS-2025-019](https://aws.amazon.com/security/security-bulletins/AWS-2025-019/) both show trust/confirmation bypass as a primary failure mode. | Validated via fixtures; public config repros should be added to the evidence queue. | Keep |
| Rule / skill maliciousness detection | Flags hidden payloads, override language, hidden Unicode, remote-shell instructions, session-transfer patterns, and similar hostile content in `SKILL.md` / rule markdown. | Mature | Strong | [Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/), [Snyk Clawdhub campaign](https://snyk.io/articles/clawdhub-malicious-campaign-ai-agent-skills/), and [Snyk skill threat model](https://snyk.io/jp/articles/skill-md-shell-access/) strongly justify this family. | Validated on live `security-review`, `frankenphp`, `browser-use`, and `remote-browser` samples. | Keep and strengthen |
| Session / cookie / profile transfer detection | Flags cookie export/import, session sharing, profile sync, real-browser reuse, and public tunnel patterns. | Mature | Strong | Live public skills such as [`browser-use`](https://github.com/browser-use/browser-use/blob/main/skills/browser-use/SKILL.md), [`remote-browser`](https://github.com/browser-use/browser-use/blob/main/skills/remote-browser/SKILL.md), and [`kernel-agent-browser`](https://github.com/kernel/skills/blob/main/plugins/kernel-cli/skills/kernel-agent-browser/SKILL.md) provide direct evidence. | Validated on all three public samples above. | Keep and strengthen |
| Bootstrap control-point detection | Flags skills that bootstrap global/latest tools, write `.claude` hooks/settings/agents or `CLAUDE.md`, and require restart to activate the new control points. | Mature | Strong | The public [`create-beads-orchestration`](https://github.com/AvivK5498/The-Claude-Protocol/blob/main/skills/create-beads-orchestration/SKILL.md) skill demonstrates this pattern directly. | Validated against the live public `create-beads-orchestration` sample after the March 7 hardening pass. | Keep and strengthen |
| IDE / workspace security settings detection | Flags risky workspace settings and AI-tool settings that turn committed repo files into execution/config vectors. | Implemented | Strong | [VS Code Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) explicitly warns that tasks, debugging, workspace settings, extensions, and AI agents can execute code from unfamiliar workspaces. | Indirect validation via discovery and fixture coverage. | Keep |
| Git hook detection | Flags suspicious repo hooks and supports allowlisting known-safe hooks. | Implemented | Strong | [Git hooks docs](https://git-scm.com/docs/githooks.html) confirm hooks are executable programs triggered by Git events; [CrowdStrike on CVE-2025-48384](https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-blocks-git-vulnerability-cve-2025-48384/) shows malicious hook placement via Git write primitives is a real attack path; [Claude Code project-file RCE](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) also highlighted hooks. | Validated by fixtures; public malicious repo examples should be added to the evidence queue. | Keep |
| Symlink escape detection | Flags symlinks from repo-controlled surfaces into sensitive local files or system paths. | Implemented | Moderate | [CrowdStrike on CVE-2025-48384](https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-blocks-git-vulnerability-cve-2025-48384/) is strong analog evidence for repo-controlled file redirection; this feature is mostly preventative hardening. | Validated by fixtures only. | Keep |
| Plugin / extension manifest provenance and integrity checks | Checks source URLs, local paths, install scripts, permissions, provenance, publisher identity, signatures, attestation, transparency, version pinning, and marketplace/domain consistency. | Implemented | Strong | [Eclipse Open VSX advisory](https://blogs.eclipse.org/post/mika%C3%ABl-barbero/eclipse-open-vsx-registry-security-advisory), [Open VSX October 2025 follow-up](https://blogs.eclipse.org/post/mika%C3%ABl-barbero/open-vsx-security-update-october-2025), [JFrog on compromised Amazon Q VS Code extension](https://research.jfrog.com/post/amazon-q-vs-code-extension-compromised-with-malicious-code/), and [ReversingLabs on malicious VS Code extensions](https://www.reversinglabs.com/blog/malicious-vs-code-fake-image) directly support this family. | Not yet revalidated with fresh live manifests in the current audit pass. | Keep and strengthen |
| Marketplace provenance / signature / attestation policy | Flags missing digest/signature/attestation metadata, issuer trust-anchor problems, transparency proof failures, bypass flags, and unstable release channels. | Implemented | Strong | Same extension-registry incidents above, especially [Open VSX](https://blogs.eclipse.org/post/mika%C3%ABl-barbero/eclipse-open-vsx-registry-security-advisory) and [JFrog’s Amazon Q extension compromise](https://research.jfrog.com/post/amazon-q-vs-code-extension-compromised-with-malicious-code/), justify stronger marketplace integrity controls. | Not yet revalidated with temp-only live manifest pulls. | Keep and strengthen |
| MCP rug-pull detection | Hashes MCP configs and reports `NEW_SERVER` / `CONFIG_CHANGE` across scans. | Mature | Strong | [Cursor MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/) is direct evidence that a previously trusted MCP entry can change behavior silently; [Invariant tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [Snyk MCP research](https://snyk.io/articles/mcp-security-research-brief-securing-tools-skill-execution/) reinforce the need for change tracking. | Validated by tests and product hardening work; not a live-sample feature in isolation. | Keep |
| MCP tool-poisoning detection | Uses deep scan to analyze remote tool descriptions for hidden or agent-visible malicious instructions. | Implemented | Strong | [Invariant Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) is direct evidence for this feature. | Validated via deterministic tests and deep-scan integration; public malicious MCP descriptions should be added to the live evidence queue. | Keep |
| Toxic-flow detection | Looks for compound attack paths where one tool/resource poisons or redirects another. | Implemented | Strong | [Invariant Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis) and [GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability) directly justify this family. | Validated in tests; live public validation still limited. | Keep and strengthen |
| Remote MCP domain / header governance | Flags non-allowlisted domains, credential-bearing headers, routing overrides, and risky remote-MCP policy combinations. | Implemented | Moderate | [AWS-2025-019](https://aws.amazon.com/security/security-bulletins/AWS-2025-019/) and [MSRC variant-hunting research](https://www.microsoft.com/en-us/msrc/blog/2025/11/msrc-variant-hunting-from-multi-tenant-authorization-to-model-context-protocol/) provide analog evidence for authorization and trust-boundary failures, but public artifact quality is weaker here. | Mostly validated by fixtures today. | Keep, but tighten scope before expanding |
| Safe local text analysis | Uses tool-less Claude to analyze local instruction files as inert text without fetching URLs or executing commands. | Partial | Strong | Strongly justified by the live public skills above, because static heuristics alone missed some cases until this path was added. | Validated on `security-review`, `browser-use`, `remote-browser`, and `create-beads-orchestration`. | Keep and expand carefully |
| Deep scan of remote resources | Fetches approved remote MCP/package metadata and runs model-assisted analysis on the fetched text/metadata. | Implemented | Strong | [Invariant Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability), and [Snyk MCP research](https://snyk.io/articles/mcp-security-research-brief-securing-tools-skill-execution/) all justify analyzing remote tool metadata. | Validated, but many public targets fail with auth/network issues before analysis. | Keep and strengthen |
| Wrapper mode / TOCTOU recheck | Scans before launch, blocks dangerous launches, and rechecks the scanned local config surface immediately before starting the tool. | Mature | Weak | This is mainly a product-control safeguard rather than a public incident-driven feature, though it directly mitigates the trust-drift pattern seen in [Cursor MCPoison](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/). | Validated by CLI tests and recent product hardening work. | Keep |
| Remediation and undo | Applies guided or safe fixes, creates backups, and restores with hash-verified undo. | Mature | Weak | Product-value feature; not threat-evidence driven. It matters because the scanner is intended to block and help users recover safely, not just detect. | Validated by Layer 4 and CLI tests. | Keep |
| Reporting and policy controls | Provides terminal/JSON/SARIF/Markdown/HTML output, suppression, OWASP shaping, allowlists, trusted directories, and domain policy overrides. | Mature | Weak | Product/usability feature, justified by operator workflow rather than external incidents. | Validated by tests and recent hardening work. | Keep |

## Current Product Read

### Tier A: strongest value, should remain central

- Rule / skill maliciousness detection
- Command-surface detection
- Consent-bypass detection
- Environment override detection
- Plugin / marketplace provenance and integrity checks
- MCP rug-pull detection
- MCP tool-poisoning and toxic-flow analysis
- Session / cookie / profile transfer detection
- Bootstrap control-point detection

### Tier B: valuable but still needs broader live-sample validation

- IDE / workspace security settings detection
- Git hook detection
- Symlink escape detection
- Deep scan of remote resources
- Remote MCP domain / header governance

### Tier C: product-control families, keep for operator value

- Wrapper mode / TOCTOU recheck
- Remediation and undo
- Reporting and policy controls

## Recommended Next Validation Queue

1. **Plugin / marketplace provenance and integrity**
   - Pull fresh public extension manifests and registry metadata into temp projects.
   - Confirm CodeGate flags missing provenance / attestation / signature controls on real samples.

2. **MCP poisoning / toxic-flow**
   - Find public MCP metadata or description examples that exercise hidden-instruction and cross-tool shadowing patterns.
   - Validate CodeGate’s deep-scan findings against those artifacts.

3. **Consent-bypass / enterprise policy surfaces**
   - Collect real public configs from Kiro, Cline, or Amazon Q ecosystems that demonstrate auto-approval or HITL-bypass patterns.

4. **Git hooks / symlink escape**
   - Find safe public repro repositories or advisories with minimal PoCs and stage only the relevant files in temp projects.

5. **Remote MCP domain / header governance**
   - Reassess whether the current granularity is worth the maintenance cost if strong public examples remain sparse.

## Provisional Product Decisions

- **Keep as-is:** cross-tool discovery, env overrides, command surfaces, consent bypass, MCP rug-pull detection, wrapper TOCTOU, remediation/undo, reporting/policy controls.
- **Keep and strengthen:** rule/skill maliciousness, session transfer, bootstrap control points, plugin marketplace provenance/integrity, MCP poisoning, toxic flow, safe local text analysis, deep remote-resource scan.
- **Keep but narrow/watch carefully:** remote MCP domain/header governance.
- **No immediate candidate for removal** surfaced in this audit, but the remote MCP header/domain policy family is the closest area to re-scope if evidence remains mostly analog rather than direct.
