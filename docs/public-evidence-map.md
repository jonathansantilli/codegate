# Public Evidence Map

This document summarizes public incident patterns that motivated CodeGate and maps them to the defensive checks CodeGate provides.

For the full feature-by-feature ledger with status and links, see [feature-evidence-ledger.md](./feature-evidence-ledger.md).

## Evidence Themes

1. Repository files can become execution paths.
2. Consent and review controls can be bypassed or weakened.
3. MCP and tool metadata can carry malicious instructions.
4. Marketplace and extension supply chains can be compromised.

## Incident-to-Capability Mapping

| Incident pattern                                          | Public examples                                          | Why it matters                                                                    | CodeGate capability families                                                                     |
| --------------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Project-file-driven command execution and secret exposure | Check Point research on Claude Code and Codex CLI CVEs   | Trusted repo files can trigger command paths users do not expect.                 | Cross-tool discovery, command-surface detection, environment override detection, wrapper recheck |
| Consent bypass and unsafe auto-approval                   | Cursor MCPoison, AWS bulletin patterns                   | Prompts and approvals can be reduced to "always allow" behavior.                  | Consent-bypass detection, policy controls, warning/threshold gating                              |
| MCP poisoning and cross-tool toxic flows                  | Invariant tool-poisoning and toxic-flow analyses         | Tool descriptions and upstream metadata can manipulate downstream agent behavior. | Deep scan, tool-description analysis, toxic-flow findings, rug-pull tracking                     |
| Malicious skill/rule content in public ecosystems         | Snyk ToxicSkills and related campaigns                   | Instruction files can hide high-impact payloads in normal markdown.               | Rule/skill maliciousness detection, local text analysis, suspicious pattern heuristics           |
| Compromised marketplace or extension integrity            | Open VSX advisories, JFrog Amazon Q extension compromise | Supply-chain trust can fail even in established ecosystems.                       | Plugin/extension provenance checks, signature/attestation policy, transparency checks            |

## Why This Matters for Users

Most users install fast and run tools quickly. They do not parse every setting, hook, skill, extension manifest, or policy file before execution. CodeGate focuses on making these hidden control surfaces visible before launch, so trust decisions are made with context.

## Scope and Limits

- CodeGate is an awareness and decision-support tool.
- It is not a complete prevention system.
- Detection quality depends on known patterns, configuration coverage, and available context.
- Deep analysis is opt-in and should be used with clear operator intent.
