# CodeGate Hardening Plan

Source of truth for the six-phase hardening effort derived from the 2026-08-19 code review.
Baseline: v0.12.4, `main` @ 9898e25. Readable report: the "CodeGate Hardening Plan" artifact
(claude.ai/code/artifact/16b98401-78f6-447a-b811-28cd98252db3).

Update the checkboxes and status lines in the same PR that lands the work.

2026-08-20: branch reconciled with upstream `main` v0.16.2 (Agent SDK meta-agent, `inventory`
command, Layer 3 fetch guards, single-file scan fixes). Upstream's `layer3_remote_fetch_*`
keys are policy keys under the Phase 1 trust model: untrusted project config cannot change
them. Upstream's silent-skip for empty Layer 3 results (#53) is preserved.

## Status

| Phase | Delivers | Status |
| ----- | -------- | ------ |
| 0 | Hygiene & performance quick wins | done (d79794c) |
| 1 | Trust boundary: scanned content cannot weaken the scan | done |
| 2 | Text normalization, hidden-Unicode coverage, encoded payloads | done |
| 3 | Skill-directory coverage | done |
| 4 | Layer 3 capability | done |
| 5 | Signed content feed (mechanism; feed repo + key pending owner decisions) | done (inert until key set) |
| 6 | Known-bad indicators + first-scan review | done |

Open owner decisions (do not block implementation, block feed launch):

- [ ] Location of the signed content feed (assumed: separate `codegate-content` repo, GitHub Releases)
- [ ] Signing-key custody (who generates and holds the Ed25519 private key)

## Phase 0 — Hygiene & performance

- [x] Remove stray `--no-cone` file from repo root
- [x] Add `reports/` to `.gitignore` (`.devcontainer/` deliberately left untracked for now)
- [x] Precompile candidate-pattern regexes in `collectSelectedCandidates` (src/scan.ts); memoize `wildcardToRegex`
- [x] Replace O(n²) `hasEquivalentFinding` with a keyed `Set` in `runStaticEngine` (src/layer2-static/engine.ts)
- [x] Acceptance: full suite green; JSON report on fixtures unchanged

## Phase 1 — Trust boundary (security fix)

- [x] Split project-config merge into cosmetic vs policy fields (src/config.ts, `PROJECT_COSMETIC_KEYS` / `PROJECT_FORBIDDEN_KEYS` + predicates)
- [x] Shared trust helper `src/config/trust.ts` (extracted from wrapper.ts); gate policy fields on global-config `trusted_directories`
- [x] `ignored_project_settings` surfaced as INFO finding `untrusted-project-config` (reaches terminal/JSON/SARIF via the report)
- [x] `suppression_source` provenance on findings (`SUPPRESSION_SOURCE` enum-style constants: inline / inline-untrusted / config)
- [x] `computeExitCode` counts untrusted inline suppressions; summary exposes `suppressed_untrusted`
- [x] `codegate trust` command (add / --list / --remove / --yes, confirmation prompt)
- [x] Fixture: malicious repo with self-allowlisting `.codegate.json` + inline ignores still exits 2 (tests/config/trust-boundary.test.ts)
- [x] Docs: docs/trust-model.md

## Phase 2 — Normalization & obfuscation resistance

- [x] `src/layer2-static/text/unicode.ts`: ZERO_WIDTH, BIDI_CONTROLS, TAG_CHARACTERS (U+E0000–E007F), clustered VARIATION_SELECTORS, `findHiddenUnicode` (escape sequences only — no literal hidden chars in source)
- [x] `src/layer2-static/text/normalize.ts`: NFKC + strip + confusables fold (data module `confusables.ts`; TS `as const` instead of JSON to avoid build-asset copying)
- [x] Shared `src/layer2-static/text/threat-patterns.ts`; rule-file + tool-description scanners match over normalized lines, evidence quotes originals
- [x] Tag-character rules `rule-file-hidden-unicode-tags` / `tool-description-hidden-unicode-tags` (HIGH)
- [x] `src/layer2-static/text/encoded-payloads.ts`: bounded base64/hex decode-and-rescan; `rule-file-encoded-payload` (CRITICAL when decoded remote shell) + `tool-description-encoded-payload`
- [x] Phrase lists moved to data (`override-phrases.ts`) with es/pt/fr/de/ru/zh/ja seeds
- [x] Evasion regression tests in tests/layer2/text-analysis.test.ts (zero-width split, homoglyphs, fullwidth, b64 curl|bash, hex override, benign clean)

## Phase 3 — Skill-directory coverage

- [x] Sibling collection for skill candidates in src/scan.ts (depth ≤ 3, ≤ 200 files, text-like extensions + shebang)
- [x] Binary payload findings `skill-binary-payload` (NUL sniff; ELF/Mach-O/PE or executable ⇒ HIGH)
- [x] `src/layer2-static/detectors/skill-frontmatter.ts`: `skill-allowed-tools-broad`, `skill-frontmatter-hidden-instructions`, `skill-frontmatter-mismatch`
- [x] `rule-file-remote-instruction-indirection` rule + URL registered as deep-scan resource (`collectIndirectionUrlResources`)
- [x] Malicious + benign skill fixtures and walk-cap test (tests/layer2/skill-coverage.test.ts); skills-wrapper reuses runScanEngine so coverage flows through

## Phase 4 — Layer 3 capability

- [x] `mcp-unpinned-package` detector (MEDIUM, offline, notes npx -y auto-confirm; skips known-safe servers) in `detectors/mcp-package-hygiene.ts`
- [x] `data/popular-mcp-packages.ts` + `text/edit-distance.ts` (Damerau-Levenshtein) + `mcp-possible-typosquat` (HIGH, offline)
- [x] `src/layer3-dynamic/registry-client.ts` (host allowlist, https only, redirect:error, 5s timeout, 1MiB streamed cap, injectable fetch, typed subset)
- [x] `createDeepResourceExecutor`: npm/pypi metadata fetched only when runtime_mode=online + per-resource consent; http/sse/git stay record-only always; consent previews updated to show the real GET
- [x] `registry-findings.ts`: package-install-scripts (HIGH), package-recently-published (config `registry_heuristics.recent_publish_days`, default 30), package-deprecated; fetch failures surface via the existing layer3 error findings (metadata-unavailable rule dropped as redundant)
- [x] Cross-server toxic flow (workspace scope, cross-origin-only, origin-labeled descriptions) + `detectToxicFlows` enumerates all chains (cap 10)
- [x] Offline-invariant tests: zero fetch calls in offline/default mode; URL resources never fetched even online (tests/layer3/no-outbound-calls.test.ts)

## Phase 5 — Signed content feed

- [x] Bundle format + Ed25519 verification (`src/content/content-bundle.ts`), publisher key placeholder (`publisher-key.ts` = null → fail closed) until owner decision
- [x] `content-updater.ts`: verify-before-parse, https-only, size/time caps, `~/.codegate/content/<version>/`, keep 2, prune
- [x] Loader resolution order: verified feed → bundled (knowledge base, rule packs via feed `rules`, override phrases, popular packages); signatures re-verified on load; any failure degrades to bundled
- [x] Real `update-kb` / `update-rules` (+ `--check`, `--rollback`, `--url` override)
- [x] `docs/content-feed.md` incl. key-custody guidance + `scripts/content-feed/` keygen and signing scripts
- [x] Tamper/wrong-key/no-key/non-https tests, prune/rollback, cold-start fallback, KB resolution-order tests (tests/content/content-feed.test.ts)

## Phase 6 — Known-bad indicators & first-scan review

- [x] `src/layer2-static/detectors/known-bad.ts` (hashes, package names, URL patterns, fingerprints) ⇒ CRITICAL `known-malicious-content`; reads local `~/.codegate/known-bad.json` until the feed exists (loader in `src/content/known-bad.ts` merges feed `known_bad` + local file)
- [x] `docs/known-bad-format.md` contribution format
- [x] `mcp-server-first-seen` findings MEDIUM on untrusted targets / INFO on trusted (`first_scan_review`, default true; disabling skips the finding but still records the baseline)
- [x] Scan-state keyed per project root (was global — v2 state-file format `{version, projects}`; legacy unkeyed files are discarded on load because honoring them would be a cross-project TOFU bypass; one-time re-baseline per project)
- [x] Indicator match (unit + local-file e2e exit 2 + feed merge), first-seen severity, cross-project no-collision, rescan-quiet tests (tests/layer2/known-bad.test.ts, tests/layer2/first-scan-review.test.ts, tests/content/content-feed.test.ts)
