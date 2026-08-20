# Trust Model: Project Config and Inline Directives

CodeGate scans content that may be adversarial. That content must never be able to
weaken its own scan. Two channels used to allow exactly that, and are now gated by
directory trust.

## Directory trust

A directory is trusted when it (or an ancestor) is listed in `trusted_directories`
in the **global** config (`~/.codegate/config.json`). Project config can never add
to the trusted list.

Manage the list with:

```bash
codegate trust               # trust the current directory (asks for confirmation)
codegate trust ./project     # trust a specific directory
codegate trust --list        # show trusted directories
codegate trust --remove ./project
```

## What project config (`.codegate.json`) can set

In any directory (trusted or not), project config may set **presentation options**:

- `output_format`
- `tui.*`
- `owasp_mapping`

Only in **trusted** directories may project config also set **policy options** —
everything that changes what is detected, suppressed, executed, or gated, including:

- `suppress_findings`, `suppression_rules`, `rules`, `skip_rules`, `allowed_rules`
- `known_safe_mcp_servers`, `known_safe_formatters`, `known_safe_lsp_servers`, `known_safe_hooks`
- `severity_threshold`, `auto_proceed_below_threshold`, `strict_collection`
- `unicode_analysis`, `check_ide_settings`, `trusted_api_domains`, `blocked_commands`
- `scan_collection_modes`, `scan_collection_kinds`, `scan_user_scope`, `scan_state_path`
- `persona`, `runtime_mode`, `workflow_audits`
- `rule_pack_paths` and `tool_discovery.*` (these point CodeGate at files and
  binaries it will read or execute — the highest-risk settings)

`trusted_directories` itself is never honored from project config.

When policy settings are ignored, the scan report includes an INFO finding
(`untrusted-project-config`) listing the ignored keys, so the signal reaches
JSON/SARIF consumers as well as the terminal.

## Inline ignore directives

`codegate: ignore[rule-id]` comments inside scanned files always mark matching
findings as suppressed in the report. However, in **untrusted** directories those
suppressions are tagged `inline-untrusted` and still count toward the exit code and
the `codegate run` launch gate. Untrusted content cannot self-approve.

The report summary exposes `suppressed_untrusted` so reporters can show how many
suppressions were requested by target-controlled directives without being honored
for gating.
