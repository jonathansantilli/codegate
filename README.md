# CodeGate

CodeGate is a pre-flight security scanner and remediation tool for AI coding tool configuration risk.

It scans project-level AI tool configs before launch and reports risky settings such as endpoint overrides, command execution surfaces, consent-bypass flags, suspicious hooks, and symlink escape paths.

## Installation

Run without global install:

```bash
npx codegate scan .
```

Install globally:

```bash
npm install -g codegate
codegate scan .
```

## System Capabilities

1. Multi-layer analysis pipeline:
Layer 1 discovery of known AI config files and installed tools.
Layer 2 static risk detection without network calls.
Layer 3 deep scan (opt-in) for external resources and meta-agent analysis.
Layer 4 remediation with backup and undo.
2. Static detections include:
`ENV_OVERRIDE`, `COMMAND_EXEC`, `CONSENT_BYPASS`, `RULE_INJECTION`, `IDE_SETTINGS`, `SYMLINK_ESCAPE`, `GIT_HOOK`, `NEW_SERVER`, `CONFIG_CHANGE`.
3. Layer 3 analysis can derive:
tool description findings, toxic flow findings (`TOXIC_FLOW`), and parse/availability findings (`PARSE_ERROR`).
It can also perform text-only analysis of local instruction files such as `AGENTS.md`, `CODEX.md`, and discovered skill/rule markdown when a safe tool-less agent mode is available.
4. Output formats:
`terminal`, `json`, `sarif`, `markdown`, `html`.
5. Wrapper mode:
`codegate run <tool>` scans first, blocks dangerous launches, rechecks the scanned config surface for post-scan file changes, and can require confirmation for warning-level findings.

## Knowledge-Base Coverage (Updated March 2, 2026)

- Expanded Layer 1 path coverage for existing tools:
`.claude/settings.local.json`, `CLAUDE.md`, `.claude/CLAUDE.md`, `.claude/plugins.json`, `AGENTS.md`, recursive markdown/rule glob support (for example `.cursor/rules/**/*.mdc`, `.codex/skills/**/*.md`, `.gemini/skills/**/*.md`, `.kiro/steering/**/*.md`, `.opencode/{rules,skills,commands}/**/*.md`, `.clinerules/**/*.md`), `.instructions.md`, `*.instructions.md`, `.github/instructions/*.instructions.md`, `.kiro/mcp.json`, `.kiro/product.json`, `.cline/marketplace.json`, Cline official global storage surfaces (`Documents/Cline/{Rules,Workflows,Hooks}` and `.cline/data/{settings,cache}` including `cline_mcp_settings.json` and `remote_config_*.json`), Copilot user-scope VS Code manifests (stable + Insiders paths under `Code` and `Code - Insiders`), Cursor user profile paths (`~/Library/Application Support/Cursor/User/{mcp,settings,extensions}.json` + Windows roaming equivalents), OpenCode/Codex XDG + AppSupport + Roaming user variants, JetBrains Junie global paths (`~/Library/Application Support/JetBrains/Junie/*`, `~/.config/JetBrains/Junie/*`) plus broader JetBrains profile/workspace mappings (for example `.idea/workspace.xml` and `~/Library/Application Support/JetBrains/**/options/aiAssistant.xml`), plus additional Windsurf/OpenCode/Copilot plugin and workflow surfaces.
- Added first-class KB entries for:
`gemini-cli`, `roo-code`, `cline`, `zed`, `jetbrains-junie`.
- Layer 3 deep resource discovery now supports MCP key aliases:
`mcpServers`, `mcp_servers`, and `context_servers` (including nested blocks).
- Layer 3 deep resource discovery also extracts organization-managed Cline `remoteMCPServers` URLs from remote-config caches.
- Layer 2 scan-state MCP baseline extraction supports the same alias key families and Cline `remoteMCPServers` snapshots.
- Layer 2 consent-bypass detection includes cross-tool auto-approval semantics:
`alwaysAllow`, `autoApprove`, `auto_approve`, and `yolo`.
- Layer 2 consent-bypass detection also covers high-impact Cline enterprise policy controls:
`mcpMarketplaceEnabled: false`, `blockPersonalRemoteMCPServers: true`, `remoteMCPServers[*].alwaysEnabled: true`, and insecure HTTP `remoteMCPServers[*].url`.
- Layer 2 consent-bypass detection includes Cline remote MCP header trust-policy signals:
credential-bearing headers (for example `Authorization`, `Cookie`, `X-API-Key`) and routing/identity override headers (for example `Host`, `Origin`, `X-Forwarded-*`) inside `remoteMCPServers[*].headers`.
- Layer 2 consent-bypass detection enforces optional organization allowlists for Cline remote MCP domains:
`remoteMCPServers[*].url` and routing header domains are validated against configured `trusted_api_domains` (with explicit rule IDs for non-allowlisted domains).
- User-scope ingestion is default-on (`scan_user_scope: true`) for home-directory config paths; use config to disable it when needed.
- Layer 2 includes plugin/extension manifest checks for insecure/untrusted source URLs (including Kiro extension-registry `extensionsGallery` endpoint fields), non-allowlisted Kiro extension-registry domains (`plugin-manifest-nonallowlisted-extension-registry`), Kiro extension-registry host mismatch across endpoint fields (`plugin-manifest-extension-registry-host-mismatch`), Kiro publisher trust-policy bypass metadata (`plugin-manifest-publisher-trust-bypass`), suspicious install scripts, local path sources, unpinned image/git references, missing integrity metadata on direct artifact downloads, missing marketplace provenance on Roo/OpenCode/Zed/Claude/Gemini plugin marketplace sources (`plugin-manifest-missing-marketplace-provenance`), wildcard permission grants, risky capability declarations, unverified publisher/signature metadata, signature-bypass flags, unscoped/version-qualified VS Code extension IDs, Zed publisher-scoped ID + publisher-identity mismatch constraints (`plugin-manifest-publisher-identity-mismatch`), invalid path/URL-like VS Code recommendation entries (`plugin-manifest-invalid-extension-id`), invalid path/URL-like package identity fields, disallowed publisher/namespace tokens, source-bearing entries missing package identity fields, unpinned/unstable version selectors, cross-marketplace source domain mismatches (`plugin-manifest-cross-marketplace-source`) with user-domain override support, user-vs-project scope severity differentiation for advisory marketplace/provenance signals, unverified attestation/provenance metadata, per-tool issuer trust-anchor validation, profile-aware incomplete attestation schema fields (compatibility ID `plugin-manifest-incomplete-attestation` plus profile IDs `plugin-manifest-incomplete-attestation-base` and `plugin-manifest-incomplete-attestation-strict`), certificate-chain failures, strict-profile certificate-policy EKU/OID constraints (including Roo strict profile), transparency-proof verification failures, transparency-bypass flags, required transparency proof metadata in strict profiles, transparency checkpoint consistency (log index/tree size and timestamp skew), and unstable release-channel/prerelease opt-ins.
- Layer 2 command-surface parsing covers command aliases used in workflow/hook DSLs (`run`, `runCommand`, `script`, `exec`, `shell`, `shellCommand`, `cmd`, `execute`, `commandLine`), object-style command templates (for example `{ "command": "...", "args": [...] }`, `{ "program": "...", "arguments": [...] }`), markdown workflow command blocks (`<execute_command><command>...</command></execute_command>`), and implicit command-template objects in executable contexts (`hooks.*`, `workflows.*`, `mcp*`, `plugins/extensions*`).
- Layer 2 allowlist matching normalizes package/server identifiers (including `node_modules` path forms and case variants) to reduce bypasses from string-shape differences.

## Core Commands

| Command | Purpose |
|---|---|
| `codegate scan [dir]` | Scan a directory for AI tool config risks. Defaults to `.`. |
| `codegate run <tool>` | Scan current directory, then launch selected AI tool if policy allows. |
| `codegate undo [dir]` | Restore the most recent remediation backup session. Defaults to `.`. |
| `codegate init` | Create `~/.codegate/config.json` with defaults. |
| `codegate update-kb` | Show knowledge-base update guidance. |
| `codegate update-rules` | Show rules update guidance. |
| `codegate --help` | Show CLI usage. |

## `scan` Command Flags

| Flag | Purpose |
|---|---|
| `--deep` | Enable Layer 3 dynamic analysis. |
| `--remediate` | Enter remediation mode after scan. |
| `--fix-safe` | Auto-fix unambiguous critical findings. |
| `--dry-run` | Show proposed fixes but write nothing. |
| `--patch` | Generate a patch file for review workflows. |
| `--no-tui` | Disable TUI and interactive prompts. |
| `--format <type>` | Output format: `terminal`, `json`, `sarif`, `markdown`, `html`. |
| `--output <path>` | Write report to file instead of stdout. |
| `--verbose` | Show extended output in terminal format. |
| `--config <path>` | Use a specific global config file path. |
| `--force` | Skip interactive confirmations. |
| `--include-user-scope` | Force-enable user/home AI tool config paths for this run (useful if config disables user-scope scanning). |
| `--reset-state` | Clear persisted scan-state history and exit. |

Examples:

```bash
codegate scan .
codegate scan . --format json
codegate scan . --format sarif --output codegate.sarif
codegate scan . --deep
codegate scan . --deep --include-user-scope
codegate scan . --deep --force
codegate scan . --remediate
codegate scan . --fix-safe
codegate scan . --remediate --dry-run --patch
codegate scan . --reset-state
```

## `run` Command

`codegate run <tool>` runs scan-first wrapper mode.

- Valid run targets: `claude`, `opencode`, `codex`, `cursor`, `windsurf`, `kiro`.
- On dangerous findings (exit threshold reached), tool launch is blocked.
- If files change between scan and launch check, launch is blocked and rescan is required.
- Warning-level findings below the blocking threshold can still require confirmation before launch.

`run` flags:

| Flag | Purpose |
|---|---|
| `--no-tui` | Disable TUI and interactive prompts. |
| `--config <path>` | Use a specific global config file path. |
| `--force` | Skip the warning-level launch confirmation prompt. |

`run` behavior notes:

- `codegate run` always renders terminal/TUI output. Machine-readable output formats are available from `codegate scan`.
- If the scan returns exit code `1` and findings exist, launch proceeds without prompting only when one of these is true:
  - `--force` is provided
  - `auto_proceed_below_threshold` is `true`
  - the current working directory is inside a configured `trusted_directories` path
- Post-scan change detection covers the same local config surface that was scanned, including selected user-scope config files when user-scope scanning is enabled.

Examples:

```bash
codegate run claude
codegate run claude --force
codegate run codex
codegate run cursor
```

## Deep Scan (Layer 3)

Deep scan is opt-in and only runs with `--deep`.

Current behavior:

- Discovers eligible external resources from known config paths.
- Discovers eligible local instruction files from the selected markdown/text scan surface.
- If no eligible resources are found, prints an explicit message and completes scan.
- In interactive mode, if supported meta-agents are installed, asks user to select one: `claude` (Claude Code), `codex` (Codex CLI), `opencode` (OpenCode via generic stdin mode).
- Prompts for per-resource deep scan consent.
- Prompts for per-command meta-agent execution consent with command preview.
- Parses meta-agent output (raw JSON or fenced JSON) and merges findings.
- If parsing or command execution fails, reports Layer 3 findings instead of crashing.
- In non-interactive mode, deep actions are skipped unless `--force` is provided.
- Use `--include-user-scope` to include user/home config surfaces in Layer 1/2 and Layer 3 resource discovery.
- Local instruction-file analysis is text-only: CodeGate passes file content and referenced URL strings as inert text and does not execute referenced content.

For MCP tool-description analysis, CodeGate does not execute untrusted MCP stdio command arrays during scanning.

Current local instruction-file agent support:
- Claude Code is supported for tool-less local text analysis.
- Codex CLI and OpenCode are not used for local text analysis until CodeGate can prove a shell-less mode for them.

Deep scan behavior is documented in this README and verified by CLI/integration tests.

## Remediation and Undo

- `--remediate` supports guided file remediation.
- `--fix-safe` applies unambiguous critical fixes automatically.
- `--dry-run` previews changes without writing.
- `--patch` writes patch-style output for review.
- Remediation writes backup sessions under `.codegate-backup/`.
- `codegate undo [dir]` restores the latest backup session.

Remediation and undo behavior is documented in this README and covered by Layer 4 + CLI tests.

## Scan-State Baseline and `--reset-state`

CodeGate maintains MCP baseline state for rug-pull detection at:

- default: `~/.codegate/scan-state.json`
- override: `scan_state_path` in config

Paths beginning with `~` resolve against the current user's home directory.

What state tracks:

- `NEW_SERVER`: first seen MCP server identifier
- `CONFIG_CHANGE`: MCP server config hash changed since prior scan

`--reset-state` clears that baseline file and exits immediately.

## Configuration

### Config File Locations

- Global config: `~/.codegate/config.json`
- Project config override: `<scan-target>/.codegate.json`

Create defaults:

```bash
codegate init
```

`init` flags:

- `--path <path>` write config to custom location
- `--force` overwrite existing config file

### Precedence and Merge Rules

- Scalar values: CLI overrides -> project config -> global config -> defaults.
- List values are merged and de-duplicated across levels.
- `trusted_directories` is global-only; project config cannot set it.
- `blocked_commands` is merged with defaults; defaults are always retained.

### Full Configuration Reference

| Key | Type | Allowed Values | Default |
|---|---|---|---|
| `severity_threshold` | string | `critical`, `high`, `medium`, `low`, `info` | `high` |
| `auto_proceed_below_threshold` | boolean | `true`, `false` | `true` |
| `output_format` | string | `terminal`, `json`, `sarif`, `markdown`, `html` | `terminal` |
| `scan_state_path` | string | file path | `~/.codegate/scan-state.json` |
| `scan_user_scope` | boolean | `true`, `false` | `true` |
| `tui.enabled` | boolean | `true`, `false` | `true` |
| `tui.colour_scheme` | string | free string (currently `default`) | `default` |
| `tui.compact_mode` | boolean | `true`, `false` | `false` |
| `tool_discovery.preferred_agent` | string | practical values: `claude`, `claude-code`, `codex`, `codex-cli`, `opencode` | `claude` |
| `tool_discovery.agent_paths` | object | map of agent key -> binary path | `{}` |
| `tool_discovery.skip_tools` | array of strings | tool keys to skip in discovery/selection | `[]` |
| `trusted_directories` | array of strings | directory paths | `[]` |
| `blocked_commands` | array of strings | command names | `["bash","sh","curl","wget","nc","python","node"]` |
| `known_safe_mcp_servers` | array of strings | package/server identifiers | prefilled |
| `known_safe_formatters` | array of strings | formatter names | prefilled |
| `known_safe_lsp_servers` | array of strings | lsp server names | prefilled |
| `known_safe_hooks` | array of strings | relative hook paths such as `.git/hooks/pre-commit` | `[]` |
| `unicode_analysis` | boolean | `true`, `false` | `true` |
| `check_ide_settings` | boolean | `true`, `false` | `true` |
| `owasp_mapping` | boolean | `true`, `false` | `true` |
| `trusted_api_domains` | array of strings | domain names | `[]` |
| `suppress_findings` | array of strings | finding IDs/fingerprints | `[]` |

### Default Config Example

```json
{
  "severity_threshold": "high",
  "auto_proceed_below_threshold": true,
  "output_format": "terminal",
  "scan_state_path": "~/.codegate/scan-state.json",
  "scan_user_scope": true,
  "tui": {
    "enabled": true,
    "colour_scheme": "default",
    "compact_mode": false
  },
  "tool_discovery": {
    "preferred_agent": "claude",
    "agent_paths": {},
    "skip_tools": []
  },
  "trusted_directories": [],
  "blocked_commands": ["bash", "sh", "curl", "wget", "nc", "python", "node"],
  "known_safe_mcp_servers": [
    "@anthropic/mcp-server-filesystem",
    "@modelcontextprotocol/server-github"
  ],
  "known_safe_formatters": ["prettier", "black", "gofmt", "rustfmt", "clang-format"],
  "known_safe_lsp_servers": ["typescript-language-server", "pyright", "rust-analyzer", "gopls"],
  "known_safe_hooks": [],
  "unicode_analysis": true,
  "check_ide_settings": true,
  "owasp_mapping": true,
  "trusted_api_domains": [],
  "suppress_findings": []
}
```

Configuration notes:

- `trusted_directories` is evaluated against resolved absolute paths and applies only to warning-level `codegate run` confirmations.
- `scan_state_path` accepts `~` and `~/...`, both of which resolve to the home directory before read/write/reset operations.
- `known_safe_hooks` matches discovered hook file paths relative to the repository root, for example `.git/hooks/pre-commit`.
- `unicode_analysis=false` disables hidden-unicode findings in Layer 2 rule-file scanning and Layer 3 tool-description scanning. Other rule-file heuristics remain enabled.
- `check_ide_settings=false` disables `IDE_SETTINGS` findings.
- `owasp_mapping=false` keeps detection behavior unchanged and emits empty `owasp` arrays in reports.

## Output Formats

- `terminal` (default)
- `json`
- `sarif`
- `markdown`
- `html`

SARIF output is designed for GitHub Code Scanning and other security tooling.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No unsuppressed findings |
| `1` | Findings exist below configured threshold |
| `2` | Findings at or above configured threshold |
| `3` | Scanner/runtime error |

## CI Integration (GitHub Actions + SARIF)

```yaml
- name: Run CodeGate
  run: codegate scan . --no-tui --format sarif --output codegate.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: codegate.sarif
```

## Manual Showcase Kit

Internal showcase packs and runbooks are intentionally kept out of the public GitHub repository.

Public quick demo (env override):

```bash
npm run build
node dist/cli.js scan . --no-tui --format json
```

## Release Process

- [CHANGELOG.md](./CHANGELOG.md)
- Public release automation: [`.github/workflows/release.yml`](./.github/workflows/release.yml)
- Internal release checklists are intentionally private.

## Security

If you discover a vulnerability in CodeGate itself, do not open a public issue first.

See [SECURITY.md](./SECURITY.md) for private disclosure.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Support

See [SUPPORT.md](./SUPPORT.md).
