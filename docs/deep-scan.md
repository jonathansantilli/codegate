# Deep Scan (Layer 3)

Deep scan is an opt-in Layer 3 capability for analyzing:
- external resources referenced by project configs (for example package registries and remote MCP endpoint metadata URLs)
- local instruction files such as `AGENTS.md`, `CODEX.md`, and discovered skill/rule markdown

## Privacy and Data Flow

Deep scan is disabled unless explicitly requested (`--deep`).

When enabled:
- CodeGate discovers candidate external resources from configuration context.
- CodeGate also discovers eligible local instruction files from the already selected markdown/text scan surface.
- CodeGate enumerates available meta-agents from installed tools (`claude`, `codex`, `opencode`) and prompts for selection in interactive mode.
- For each resource, CodeGate presents a per-resource consent decision.
- For each approved resource, CodeGate shows the meta-agent command preview and requires command-level approval.
- No network request or meta-agent command is executed without approval.
- In non-interactive mode, deep-scan actions are skipped unless `--force` is provided.
- Tool-description acquisition never executes untrusted MCP stdio command arrays; local stdio paths are treated as static metadata targets only.
- Local instruction-file analysis is text-only. CodeGate passes file content and referenced URL strings as inert text; it does not execute referenced content.

Data handling model:
- Local Layer 1+2 scanning remains offline.
- Layer 3 only sends the minimum resource locator and analysis prompt needed for metadata inspection.
- For local instruction files, Layer 3 sends the file path, file content, and extracted URL strings only.
- Results are merged back into the local report as Layer 3 findings.

## Consent Model

For each deep-scan action:
- user sees resource ID and fetch preview
- user chooses meta-agent (interactive mode; defaults to configured preferred agent)
- user sees the exact meta-agent command preview
- user approves or skips
- skipped resources are recorded as `skipped_without_consent` outcomes

If no eligible external resources are discovered, CodeGate reports that explicitly and exits deep mode cleanly.

Current local instruction-file agent support:
- Claude Code: supported for tool-less local text analysis (`--tools=`)
- Codex CLI: intentionally not used for local text analysis because CodeGate has not proven a shell-less mode
- OpenCode: not used for local text analysis until a tool-less mode is proven

## Failure Modes

Layer 3 outcomes are normalized into findings for reporting:
- consent skipped
- timeout
- auth failure
- network/command failure
- response schema mismatch

These are tracked as Layer 3 parse/error findings so operators can audit why deep scan did not fully complete.

## CLI

```bash
codegate scan . --deep
codegate scan . --deep --force
```
