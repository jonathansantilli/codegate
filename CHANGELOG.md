## [1.3.2](https://github.com/jonathansantilli/codegate/compare/v1.3.1...v1.3.2) (2026-08-31)

## [1.3.1](https://github.com/jonathansantilli/codegate/compare/v1.3.0...v1.3.1) (2026-08-31)

# [1.3.0](https://github.com/jonathansantilli/codegate/compare/v1.2.4...v1.3.0) (2026-08-30)

### Features

- **fleet:** read the server's collection policy, and keep our own ceiling ([cd8394d](https://github.com/jonathansantilli/codegate/commit/cd8394d4495a9f8066b7811052cd00130540c466))

## [1.2.4](https://github.com/jonathansantilli/codegate/compare/v1.2.3...v1.2.4) (2026-08-26)

## [1.2.3](https://github.com/jonathansantilli/codegate/compare/v1.2.2...v1.2.3) (2026-08-26)

### Bug Fixes

- **fleet:** bound the token an enrolling server can make us write ([#124](https://github.com/jonathansantilli/codegate/issues/124)) ([9e91067](https://github.com/jonathansantilli/codegate/commit/9e91067b40991a0c259c7bb9fb9ba148f9acac8c))

## [1.2.2](https://github.com/jonathansantilli/codegate/compare/v1.2.1...v1.2.2) (2026-08-25)

## [1.2.1](https://github.com/jonathansantilli/codegate/compare/v1.2.0...v1.2.1) (2026-08-25)

### Bug Fixes

- **fleet:** read the machine id without checking first ([#121](https://github.com/jonathansantilli/codegate/issues/121)) ([5310c8e](https://github.com/jonathansantilli/codegate/commit/5310c8eac4d6a5008672618c303bf6abe7ebca9c))

# [1.2.0](https://github.com/jonathansantilli/codegate/compare/v1.1.0...v1.2.0) (2026-08-25)

### Features

- **fleet:** report inventory and findings to a Guardian server ([#120](https://github.com/jonathansantilli/codegate/issues/120)) ([4ba8402](https://github.com/jonathansantilli/codegate/commit/4ba8402c691df62ccd1c4b0eb13cd6495e378d1b))

# [1.1.0](https://github.com/jonathansantilli/codegate/compare/v1.0.2...v1.1.0) (2026-08-20)

### Features

- **content:** pin content-feed publisher public key ([#115](https://github.com/jonathansantilli/codegate/issues/115)) ([6250414](https://github.com/jonathansantilli/codegate/commit/62504144b761f81bc79e4f05fdd858974024e5b2))

## [1.0.2](https://github.com/jonathansantilli/codegate/compare/v1.0.1...v1.0.2) (2026-08-20)

## [1.0.1](https://github.com/jonathansantilli/codegate/compare/v1.0.0...v1.0.1) (2026-08-20)

# [1.0.0](https://github.com/jonathansantilli/codegate/compare/v0.16.2...v1.0.0) (2026-08-20)

- feat(security)!: hardening phases 0-6 — trust boundary, obfuscation resistance, skill coverage, layer 3 capability, signed content feed, known-bad indicators ([#111](https://github.com/jonathansantilli/codegate/issues/111)) ([ec15cc6](https://github.com/jonathansantilli/codegate/commit/ec15cc6ff38ab6c6c3671505db083b4c000d0c47))

### Bug Fixes

- **deps:** patch dependency vulnerabilities via npm audit fix ([#112](https://github.com/jonathansantilli/codegate/issues/112)) ([dfa6549](https://github.com/jonathansantilli/codegate/commit/dfa654909bebca11824869c1cf2ab7536c1aacbb))

### BREAKING CHANGES

- .codegate.json policy settings in directories not
  listed in the global trusted_directories are now ignored (reported as
  an INFO finding). Run codegate trust <dir> to restore them.

- feat(detection): normalization-first text analysis with full hidden-unicode coverage

* new shared text core (src/layer2-static/text/): hidden-unicode classes
  incl. the previously undetected Tags block U+E0000-E007F (ASCII
  smuggling) and clustered variation selectors; NFKC + strip +
  confusable-fold normalization; shared threat patterns; data-driven
  override phrases with non-English seeds
* rule-file and tool-description scanners now match against normalized
  lines (evidence still quotes originals), so zero-width splits,
  homoglyphs, and fullwidth forms no longer evade phrase detection
* bounded base64/hex decode-and-rescan flags encoded payloads
  (CRITICAL when the decoded content is a remote-shell instruction)
* meta-agent prompt sanitizer reuses the shared hidden-char stripper

- feat(detection): scan skill directories beyond the markdown entry point

* skill candidates now pull in text-like sibling files (scripts, nested
  docs; depth<=3, 200-file cap, symlinks skipped) so payloads in
  scripts/helper.sh run through the rule-file detectors
* binary artifacts in skill directories are flagged (skill-binary-payload,
  HIGH for ELF/Mach-O/PE or executable files)
* new skill-frontmatter detector: unqualified shell / wildcard
  allowed-tools grants (HIGH), override or remote-shell language hidden
  in frontmatter metadata (HIGH), name/directory mismatch (INFO)
* rule files that tell the agent to fetch-and-follow remote instructions
  get rule-file-remote-instruction-indirection (HIGH) and the URL is
  registered as a consent-gated deep-scan resource

- feat(layer3): real package analysis with strict network guarantees

Offline (default) gains two supply-chain detectors that need no network:

- mcp-unpinned-package (MEDIUM): npx/uvx/pipx MCP servers without an
  exact version pin execute whatever the registry serves at launch;
  notes npx -y auto-confirm and skips known_safe_mcp_servers
- mcp-possible-typosquat (HIGH): Damerau-Levenshtein match against a
  curated popular-MCP-package list

Online mode (runtime_mode=online + existing per-resource consent) now
actually fetches npm/pypi registry metadata through a hardened client:
pinned hosts only, https only, redirects rejected, 5s timeout, 1MiB
streamed body cap, typed subset returned. Derived findings:
package-install-scripts (HIGH), package-deprecated,
package-recently-published (registry_heuristics.recent_publish_days).
URL/sse/git resources are never fetched in any mode, and consent
previews now show the real request.

Toxic-flow analysis enumerates all chains (was: first-only via .find)
and adds a workspace-scope cross-server pass so chains whose links live
on different MCP servers are no longer invisible.

- feat(content): signed remote content feed with verify-before-parse

Detection content (KB entries, rules, override phrases, popular-package
lists, known-bad indicators) can now ship between releases as a single
Ed25519-signed bundle:

- src/content/: bundle format + signature verification (always before
  parsing), store under ~/.codegate/content/<version> keeping the two
  newest versions, updater with https-only, size- and time-capped
  downloads; scanning never fetches - only the explicit commands do
- update-kb / update-rules are now real (--check, --rollback, --url);
  they fail closed while the publisher key placeholder is null
- loaders prefer the active verified bundle and degrade to bundled
  content on any failure; signatures are re-verified on every load
- scripts/content-feed/ has keygen + signing helpers; docs/content-feed.md
  documents format, key custody, and the two pending owner decisions

* feat(detection): known-bad indicator matching and first-scan review

Known-bad indicators (CRITICAL known-malicious-content):

- New always-on detector matches scanned files against known-malicious
  SHA-256 file hashes, MCP package names, and URL patterns, and
  escalates findings whose stable fingerprint appears in the indicator
  set. Indicators merge from the signed content feed's known_bad block
  and a local ~/.codegate/known-bad.json (user-trusted, works before
  the feed is live); malformed indicator data degrades to the valid
  subset and never breaks scanning.

First-scan review (trust-on-first-use fix):

- mcp-server-first-seen is now MEDIUM for untrusted targets and INFO
  for trusted ones, gated by first_scan_review (default true; disabling
  skips the finding but still records the baseline).
- Scan-state is now keyed per project root (v2 state-file format).
  Previously baselines were global, so a server first seen in one
  project silently passed first-seen review in every other project.
  Legacy unkeyed state files are discarded on load (they carry no
  project provenance); the cost is a one-time re-baseline per project.

docs/known-bad-format.md documents the indicator format and
contribution flow.

- docs(plan): fix phase 0 commit reference after amend

- test: make trust-command and content-feed tests Windows-portable

Trust-command fixtures resolve their paths instead of assuming POSIX
roots, and temp-home helpers override USERPROFILE alongside HOME
because os.homedir() reads USERPROFILE on Windows. Fixes the
windows-latest CI matrix.

## [0.16.2](https://github.com/jonathansantilli/codegate/compare/v0.16.1...v0.16.2) (2026-08-17)

## [0.16.1](https://github.com/jonathansantilli/codegate/compare/v0.16.0...v0.16.1) (2026-08-17)

# [0.16.0](https://github.com/jonathansantilli/codegate/compare/v0.15.2...v0.16.0) (2026-04-23)

### Features

- **layer3:** run Claude meta-agent via Agent SDK instead of CLI spawn ([#58](https://github.com/jonathansantilli/codegate/issues/58)) ([5e3c6c8](https://github.com/jonathansantilli/codegate/commit/5e3c6c81a0ae7f44c0d9be1ca3b9e3ee72b059de)), closes [openai/codex#7144](https://github.com/openai/codex/issues/7144)

## [0.15.2](https://github.com/jonathansantilli/codegate/compare/v0.15.1...v0.15.2) (2026-04-23)

## [0.15.1](https://github.com/jonathansantilli/codegate/compare/v0.15.0...v0.15.1) (2026-04-23)

# [0.15.0](https://github.com/jonathansantilli/codegate/compare/v0.14.4...v0.15.0) (2026-04-22)

### Features

- **kb:** add OpenClaw — messaging-channel gateway for LLM agents ([#56](https://github.com/jonathansantilli/codegate/issues/56)) ([854505f](https://github.com/jonathansantilli/codegate/commit/854505f28bd2e86534e6a1ece615dea27f50ee47))

## [0.14.4](https://github.com/jonathansantilli/codegate/compare/v0.14.3...v0.14.4) (2026-04-22)

### Bug Fixes

- **scan:** close cross-scan leak for single-file targets of any format ([#55](https://github.com/jonathansantilli/codegate/issues/55)) ([46e2148](https://github.com/jonathansantilli/codegate/commit/46e2148e6fc57d27a0b47a63ebbc095ed9fd83a7)), closes [#54](https://github.com/jonathansantilli/codegate/issues/54) [#54](https://github.com/jonathansantilli/codegate/issues/54)

## [0.14.3](https://github.com/jonathansantilli/codegate/compare/v0.14.2...v0.14.3) (2026-04-22)

### Bug Fixes

- **scan:** disable user-scope walk when CLI scans a single file ([#54](https://github.com/jonathansantilli/codegate/issues/54)) ([6799651](https://github.com/jonathansantilli/codegate/commit/67996514e24aaef3ff39a7c171f9bb34b5b56ace))

## [0.14.2](https://github.com/jonathansantilli/codegate/compare/v0.14.1...v0.14.2) (2026-04-22)

### Bug Fixes

- **scan:** stop attributing host-wide findings to per-target scans ([#53](https://github.com/jonathansantilli/codegate/issues/53)) ([77f9627](https://github.com/jonathansantilli/codegate/commit/77f962761c35a96fb6e8d8ec074781591785d593))

## [0.14.1](https://github.com/jonathansantilli/codegate/compare/v0.14.0...v0.14.1) (2026-04-22)

### Bug Fixes

- **layer3:** clean remote-resource URLs + configurable timeout & byte-size guards ([#52](https://github.com/jonathansantilli/codegate/issues/52)) ([750c422](https://github.com/jonathansantilli/codegate/commit/750c4229d6c08f7fa4fc58e3922394bce5b66647))

# [0.14.0](https://github.com/jonathansantilli/codegate/compare/v0.13.0...v0.14.0) (2026-04-21)

### Features

- **cli:** add `inventory` subcommand to enumerate KB-known AI artifacts ([#51](https://github.com/jonathansantilli/codegate/issues/51)) ([620b112](https://github.com/jonathansantilli/codegate/commit/620b1127e14200273e9fe899da5487d1c4cd5d2b))

# [0.13.0](https://github.com/jonathansantilli/codegate/compare/v0.12.4...v0.13.0) (2026-04-21)

### Features

- **knowledge-base:** recognize Anthropic Skills layout for claude-code ([#49](https://github.com/jonathansantilli/codegate/issues/49)) ([8762adf](https://github.com/jonathansantilli/codegate/commit/8762adf7da9b0302f0891a8614863511f8107a12))

## [0.12.4](https://github.com/jonathansantilli/codegate/compare/v0.12.3...v0.12.4) (2026-03-24)

## [0.12.3](https://github.com/jonathansantilli/codegate/compare/v0.12.2...v0.12.3) (2026-03-24)

## [0.12.2](https://github.com/jonathansantilli/codegate/compare/v0.12.1...v0.12.2) (2026-03-24)

## [0.12.1](https://github.com/jonathansantilli/codegate/compare/v0.12.0...v0.12.1) (2026-03-24)

# [0.12.0](https://github.com/jonathansantilli/codegate/compare/v0.11.0...v0.12.0) (2026-03-23)

### Features

- **workflow:** harden GitHub Actions supply-chain detections ([ca6233e](https://github.com/jonathansantilli/codegate/commit/ca6233ebeac557c8ed4ee4b19ed46d734538f996))

# [0.11.0](https://github.com/jonathansantilli/codegate/compare/v0.10.0...v0.11.0) (2026-03-23)

### Features

- **wrapper:** add scan-option parity for skills and clawhub ([3eeacc1](https://github.com/jonathansantilli/codegate/commit/3eeacc1a5e7e7e6909354458cf7c5e5139f0f74f))

# [0.10.0](https://github.com/jonathansantilli/codegate/compare/v0.9.1...v0.10.0) (2026-03-23)

### Features

- **workflow:** add artifact trust-chain and call-boundary audits ([203bc43](https://github.com/jonathansantilli/codegate/commit/203bc431c0c0cfd17e6ef7d8620715b6b56c25f9))
- **workflow:** add secret exfiltration workflow audit ([25bf6f8](https://github.com/jonathansantilli/codegate/commit/25bf6f8aeb0807d8c21449e9c4b7de91ec62650f))
- **workflow:** add wave-f foundations and pr-target checkout detector ([ebb3c68](https://github.com/jonathansantilli/codegate/commit/ebb3c68f4a0b477da85fe4f92fc211ad684f916e))
- **workflow:** complete wave-f detector set ([7e5775e](https://github.com/jonathansantilli/codegate/commit/7e5775e4e048a689c3102380809cd3f486fc8dbe))

## [0.9.1](https://github.com/jonathansantilli/codegate/compare/v0.9.0...v0.9.1) (2026-03-23)

### Bug Fixes

- **build:** copy static rule packs into dist assets ([af1de0a](https://github.com/jonathansantilli/codegate/commit/af1de0a0fa5023d067ba2a84635bdd427f7e99cb))

# [0.9.0](https://github.com/jonathansantilli/codegate/compare/v0.8.0...v0.9.0) (2026-03-23)

### Features

- add workflow audit pack with real-case validation ([a9ab51a](https://github.com/jonathansantilli/codegate/commit/a9ab51ade8d04e390608652ddac9d60fc4608f4f))

# [0.8.0](https://github.com/jonathansantilli/codegate/compare/v0.7.0...v0.8.0) (2026-03-22)

### Features

- uplift scan methodology with fingerprints, policy rules, advisories, and scan-content ([#28](https://github.com/jonathansantilli/codegate/issues/28)) ([f3cf1b1](https://github.com/jonathansantilli/codegate/commit/f3cf1b18b1efdf44887b0e21ea2f3d1a8471fbb5))

# [0.7.0](https://github.com/jonathansantilli/codegate/compare/v0.6.1...v0.7.0) (2026-03-17)

### Features

- harden deep scan security — agent sandboxing, evidence verification, no outbound HTTP ([#26](https://github.com/jonathansantilli/codegate/issues/26)) ([b5a7a42](https://github.com/jonathansantilli/codegate/commit/b5a7a42fe68ec35a1e38a78116188ac294f69f29))

## [0.6.1](https://github.com/jonathansantilli/codegate/compare/v0.6.0...v0.6.1) (2026-03-16)

# [0.6.0](https://github.com/jonathansantilli/codegate/compare/v0.5.0...v0.6.0) (2026-03-15)

### Features

- add deep analysis support to skills and clawhub wrappers ([#22](https://github.com/jonathansantilli/codegate/issues/22)) ([bc756e0](https://github.com/jonathansantilli/codegate/commit/bc756e00e4205b1ab9a43b2e2e247f11fbb5b83e))

# [0.5.0](https://github.com/jonathansantilli/codegate/compare/v0.4.0...v0.5.0) (2026-03-15)

### Features

- **cli:** add scan-first clawhub install wrapper ([#21](https://github.com/jonathansantilli/codegate/issues/21)) ([0a98771](https://github.com/jonathansantilli/codegate/commit/0a987714f6c267ca843d450d6d3701dc92d0abc6))

# [0.4.0](https://github.com/jonathansantilli/codegate/compare/v0.3.1...v0.4.0) (2026-03-14)

### Features

- separate URL target and local host findings in scan output ([#20](https://github.com/jonathansantilli/codegate/issues/20)) ([e3a2633](https://github.com/jonathansantilli/codegate/commit/e3a26336075cee9050c2802574b44e36c1023096))

## [0.3.1](https://github.com/jonathansantilli/codegate/compare/v0.3.0...v0.3.1) (2026-03-14)

# [0.3.0](https://github.com/jonathansantilli/codegate/compare/v0.2.3...v0.3.0) (2026-03-14)

### Features

- add skills wrapper preflight hardening ([#19](https://github.com/jonathansantilli/codegate/issues/19)) ([a61a255](https://github.com/jonathansantilli/codegate/commit/a61a2554fa6067af2537850bb8ed948e8b040a81))

## [0.2.3](https://github.com/jonathansantilli/codegate/compare/v0.2.2...v0.2.3) (2026-03-10)

## [0.2.2](https://github.com/jonathansantilli/codegate/compare/v0.2.1...v0.2.2) (2026-03-10)

## [0.2.1](https://github.com/jonathansantilli/codegate/compare/v0.2.0...v0.2.1) (2026-03-10)

# [0.2.0](https://github.com/jonathansantilli/codegate/compare/v0.1.9...v0.2.0) (2026-03-08)

### Features

- **scan:** add skill-aware GitHub URL targeting ([2039ee0](https://github.com/jonathansantilli/codegate/commit/2039ee0224af84d659ffff0dc1d4861b1326b099))

## [0.1.9](https://github.com/jonathansantilli/codegate/compare/v0.1.8...v0.1.9) (2026-03-08)

## [0.1.8](https://github.com/jonathansantilli/codegate/compare/v0.1.7...v0.1.8) (2026-03-08)

## [0.1.7](https://github.com/jonathansantilli/codegate/compare/v0.1.6...v0.1.7) (2026-03-08)

### Bug Fixes

- add codegate-ai bin alias for npx invocation ([3dc27ab](https://github.com/jonathansantilli/codegate/commit/3dc27abd859d54798a142ded1f117012f12bb59e))

## [0.1.6](https://github.com/jonathansantilli/codegate/compare/v0.1.5...v0.1.6) (2026-03-08)

### Bug Fixes

- run CLI when invoked through symlinked bin ([a177029](https://github.com/jonathansantilli/codegate/commit/a17702935766aa3c2d1d2278ca52aeb5bd815526))

## [0.1.5](https://github.com/jonathansantilli/codegate/compare/v0.1.4...v0.1.5) (2026-03-08)

## [0.1.4](https://github.com/jonathansantilli/codegate/compare/v0.1.3...v0.1.4) (2026-03-08)

## [0.1.3](https://github.com/jonathansantilli/codegate/compare/v0.1.2...v0.1.3) (2026-03-08)

## [0.1.2](https://github.com/jonathansantilli/codegate/compare/v0.1.1...v0.1.2) (2026-03-08)

## [0.1.1](https://github.com/jonathansantilli/codegate/compare/v0.1.0...v0.1.1) (2026-03-08)

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- Layer 4 remediation now composes multiple same-file fixes against evolving file content instead of dropping later plans.
- Layer 4 remediation now loads and edits `source_config.file_path` targets for Layer 3 findings.
- `scan_state_path` now resolves `~` and `~/...` against the user's home directory for read, write, and reset operations.
- `codegate run <tool>` now snapshots the scanned config surface, including selected user-scope config files, before launch TOCTOU checks.

### Changed

- `codegate run <tool>` is terminal/TUI only and no longer documents machine-readable `--format` output.
- `codegate run <tool>` can require explicit confirmation for warning-level findings when `auto_proceed_below_threshold` is disabled and the cwd is not covered by `trusted_directories`.
- `--force` on `codegate run <tool>` now skips the warning-level launch confirmation prompt.
- Wrapper scans and `scan` now honor granular policy controls for `suppression_rules`, `rule_pack_paths`, `allowed_rules`, and `skip_rules` through the resolved config.
- `codegate scan [target]` now accepts safely staged artifact targets in addition to local directories, including local files, remote file URLs, and git repository URLs.
- When `codegate scan [target]` is given a skill/plugin-style entrypoint file, it now stages and scans the containing artifact folder recursively instead of analyzing only the entrypoint file.

### Added

- Config toggles now control delivered behavior for `known_safe_hooks`, `unicode_analysis`, `check_ide_settings`, and `owasp_mapping`.
- Layer 2 rule-file analysis now catches hidden comment payloads, remote download-to-shell instructions, and clustered cookie/session transfer guidance in local instruction files.
- `codegate scan --deep` now supports text-only local instruction-file analysis for discovered markdown/text rule surfaces when a tool-less agent mode is available.

### Security

- Local instruction-file deep analysis now treats file content and referenced URLs as inert text and does not execute referenced content.
- Codex CLI is intentionally excluded from the new local instruction-file analysis path until a shell-less mode is proven; Claude Code is used for that path because it can run with tools disabled.

### Performance

- `codegate scan --deep` now reuses prepared Layer 1 discovery context between the main scan and deep resource discovery.
- `codegate scan` now reuses one prepared discovery context across static scanning and deep-scan target discovery.

## [0.2.2] - 2026-02-28

### Added

- MCP rug-pull state tracking with `NEW_SERVER`/`CONFIG_CHANGE` findings and `codegate scan --reset-state`.
- Configurable scan-state path support via `scan_state_path`.
- Layer 3 tool-description derived findings (`RULE_INJECTION`) and Toxic Flow Analysis (`TOXIC_FLOW`) from `metadata.tools[]`.
- `--deep` now performs consent-gated endpoint discovery, execution, and Layer 3 finding merge in the main scan flow.
- New CLI commands: `init`, `update-kb`, and `update-rules`.
- Build now copies runtime assets (knowledge base + prompt templates) into `dist`.
- Addendum documentation updates, including Snyk Agent Scan competitive positioning and v2.2 release checklist.

## [0.2.0] - 2026-02-28

### Added

- Layer 3 dynamic resource fetcher with retry strategy and auth/timeout failure normalization.
- Consent-gated deep scan orchestration to prevent network execution without explicit approval.
- Meta-agent command builder with tool-specific safety flags and prompt template system.
- Pipeline integration for Layer 3 outcome parsing and merged reporting across layers.
- Deep scan documentation with data-flow and privacy disclosure.

## [0.1.5] - 2026-02-28

### Added

- Layer 4 remediation planner and action engine (`remove_field`, `replace_value`, `strip_unicode`, `quarantine`).
- Unified diff generation for remediation output and patch workflows.
- Backup session manager with SHA-256 manifest verification and latest-session undo command support.
- CLI remediation flag wiring for `--remediate`, `--fix-safe`, `--dry-run`, and `--patch`.
- Remediation documentation and end-to-end detect/remediate/undo test coverage.

## [0.1.0] - 2026-02-28

### Added

- Core TypeScript CLI scaffolding with `scan` and `run` commands.
- Layer 1+2 scan pipeline: knowledge-base loading, file discovery/parsing, static detectors, and report summary generation.
- Reporters: terminal, JSON, SARIF, Markdown, and HTML.
- Wrapper flow for `codegate run <tool>` with target validation and TOCTOU re-check before launch.
- TUI shell components (`dashboard`, `progress`, `summary`) with non-TTY and `--no-tui` fallback behavior.
- Performance and reliability coverage for scan-time thresholds and signal-handler registration.
- OSS governance files, CI matrix, release dry-run workflow, and npm release workflow.

### Notes

- This is the first public pre-release baseline for open-source iteration.

- Release pipeline probe: 2026-03-08T16:52:38Z
