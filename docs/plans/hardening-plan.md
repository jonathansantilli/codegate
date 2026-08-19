# CodeGate Hardening Plan

Source of truth for the six-phase hardening effort derived from the 2026-08-19 code review.
Baseline: v0.12.4, `main` @ 9898e25. Readable report: the "CodeGate Hardening Plan" artifact
(claude.ai/code/artifact/16b98401-78f6-447a-b811-28cd98252db3).

Update the checkboxes and status lines in the same PR that lands the work.

## Status

| Phase | Delivers | Status |
| ----- | -------- | ------ |
| 0 | Hygiene & performance quick wins | done (47b72dd) |
| 1 | Trust boundary: scanned content cannot weaken the scan | done |
| 2 | Text normalization, hidden-Unicode coverage, encoded payloads | done |
| 3 | Skill-directory coverage | done |
| 4 | Layer 3 capability | pending |
| 5 | Signed content feed (mechanism; feed repo + key pending owner decisions) | pending |
| 6 | Known-bad indicators + first-scan review | pending |

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

- [ ] `mcp-package-pinning` detector (MEDIUM, offline)
- [ ] `popular-mcp-packages.json` + `edit-distance.ts` + `mcp-possible-typosquat` (HIGH, offline)
- [ ] `src/layer3-dynamic/registry-client.ts` (host allowlist, https, no redirects, 5s, 1MiB, injectable fetch)
- [ ] Wire client into default `executeDeepResource` for npm/pypi when online + consent; URLs stay record-only
- [ ] `registry-findings.ts`: install-scripts (HIGH), recently-published, deprecated, metadata-unavailable
- [ ] Cross-server toxic flow + enumerate all chains in `detectToxicFlows`
- [ ] Offline-invariant test: zero network calls in default mode

## Phase 5 — Signed content feed

- [ ] Bundle format + Ed25519 verification (`src/content/`), publisher key placeholder until owner decision
- [ ] `content-updater.ts`: verify-before-parse, `~/.codegate/content/<version>/`, keep 2, atomic
- [ ] Loader resolution order: verified feed → bundled (knowledge base, rule packs, phrase lists, popular packages)
- [ ] Real `update-kb` / `update-rules` (+ `--check`, `--rollback`)
- [ ] `docs/content-feed.md` incl. key-custody guidance
- [ ] Tamper/wrong-key/truncation tests; cold-start fallback test

## Phase 6 — Known-bad indicators & first-scan review

- [ ] `src/layer2-static/detectors/known-bad.ts` (hashes, package names, URL patterns, fingerprints) ⇒ CRITICAL `known-malicious-content`; reads local `~/.codegate/known-bad.json` until the feed exists
- [ ] `docs/known-bad-format.md` contribution format
- [ ] `mcp-server-first-seen` findings on first scan of untrusted targets (`first_scan_review`, default true)
- [ ] Scan-state keyed per project root (verify + fix if global)
- [ ] Indicator match / first-seen / no-collision tests
