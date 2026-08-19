# CodeGate Hardening Plan

Source of truth for the six-phase hardening effort derived from the 2026-08-19 code review.
Baseline: v0.12.4, `main` @ 9898e25. Readable report: the "CodeGate Hardening Plan" artifact
(claude.ai/code/artifact/16b98401-78f6-447a-b811-28cd98252db3).

Update the checkboxes and status lines in the same PR that lands the work.

## Status

| Phase | Delivers | Status |
| ----- | -------- | ------ |
| 0 | Hygiene & performance quick wins | in progress |
| 1 | Trust boundary: scanned content cannot weaken the scan | pending |
| 2 | Text normalization, hidden-Unicode coverage, encoded payloads | pending |
| 3 | Skill-directory coverage | pending |
| 4 | Layer 3 capability | pending |
| 5 | Signed content feed (mechanism; feed repo + key pending owner decisions) | pending |
| 6 | Known-bad indicators + first-scan review | pending |

Open owner decisions (do not block implementation, block feed launch):

- [ ] Location of the signed content feed (assumed: separate `codegate-content` repo, GitHub Releases)
- [ ] Signing-key custody (who generates and holds the Ed25519 private key)

## Phase 0 — Hygiene & performance

- [ ] Remove stray `--no-cone` file from repo root
- [ ] Add `reports/` to `.gitignore` (`.devcontainer/` deliberately left untracked for now)
- [ ] Precompile candidate-pattern regexes in `collectSelectedCandidates` (src/scan.ts); memoize `wildcardToRegex`
- [ ] Replace O(n²) `hasEquivalentFinding` with a keyed `Set` in `runStaticEngine` (src/layer2-static/engine.ts)
- [ ] Acceptance: full suite green; JSON report on fixtures unchanged

## Phase 1 — Trust boundary (security fix)

- [ ] Split project-config merge into cosmetic vs policy fields (src/config.ts)
- [ ] Shared trust helper `src/config/trust.ts` (extracted from wrapper.ts); gate policy fields on global-config `trusted_directories`
- [ ] `ignored_project_settings` surfaced as INFO finding `untrusted-project-config` + stderr notice
- [ ] `suppression_source` provenance on findings (inline / project-config / global-config)
- [ ] `computeExitCode` + run-policy gating ignore untrusted suppressions; summary splits suppressed counts by source
- [ ] `codegate trust` command (add / --list / --remove)
- [ ] Fixture: malicious repo with self-allowlisting `.codegate.json` + inline ignores still exits 2 and blocks `codegate run`
- [ ] Docs: what project config can and cannot do

## Phase 2 — Normalization & obfuscation resistance

- [ ] `src/layer2-static/text/unicode.ts`: ZERO_WIDTH, BIDI_CONTROLS, TAG_CHARACTERS (U+E0000–E007F), VARIATION_SELECTORS, `findHiddenUnicode`
- [ ] `src/layer2-static/text/normalize.ts`: NFKC + strip + confusables fold (data: `confusables.json`)
- [ ] Shared `src/layer2-static/text/threat-patterns.ts`; rule-file + tool-description scanners consume it over normalized text
- [ ] Tag-character rule `hidden-unicode-tag-smuggling` (HIGH)
- [ ] `src/layer2-static/text/encoded-payloads.ts`: bounded base64/hex decode-and-rescan; `rule-file-encoded-payload`
- [ ] Phrase lists moved to data (`override-phrases.json`) with non-English seeds
- [ ] Evasion regression tests (zero-width-split phrase, homoglyphs, b64 curl|bash); no new findings on benign fixtures

## Phase 3 — Skill-directory coverage

- [ ] Sibling collection for skill candidates in src/scan.ts (depth ≤ 3, ≤ 200 files, text-like extensions + shebang)
- [ ] Binary payload findings `skill-binary-payload` (NUL sniff; ELF/Mach-O/PE or executable ⇒ HIGH)
- [ ] `src/layer2-static/detectors/skill-frontmatter.ts`: `skill-allowed-tools-broad`, `skill-frontmatter-hidden-instructions`, `skill-frontmatter-mismatch`
- [ ] Remote-instruction indirection rule + URL registered as deep-scan resource
- [ ] Malicious + benign skill fixtures; walk-cap test; skills-wrapper e2e

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
