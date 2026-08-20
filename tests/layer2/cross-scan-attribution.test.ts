import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import { runScanEngine } from "../../src/scan";

/**
 * These tests pin down the fix for the cross-scan finding-attribution bug.
 *
 * User-scope patterns (e.g. `~/.agents/skills/&ast;/SKILL.md`) walk the user's
 * entire home directory. When the scan target itself is a specific path
 * inside the home directory — for example a single skill at
 * `~/.codex/skills/<name>` — wildcard matches for sibling skills belong to
 * completely different scans and must not be attributed to the current scan.
 *
 * The scenarios below simulate scanning one skill while a sibling skill that
 * contains hidden Unicode also exists on the host, and assert that only the
 * in-target finding is reported.
 */

const BASE_CONFIG: CodeGateConfig = {
  severity_threshold: "high",
  auto_proceed_below_threshold: true,
  output_format: "terminal",
  scan_state_path: "/tmp/codegate-cross-scan-state.json",
  tui: { enabled: false, colour_scheme: "default", compact_mode: false },
  tool_discovery: { preferred_agent: "claude", agent_paths: {}, skip_tools: [] },
  trusted_directories: [],
  blocked_commands: ["bash", "sh", "curl", "wget", "nc", "python", "node"],
  known_safe_mcp_servers: [],
  known_safe_formatters: [],
  known_safe_lsp_servers: [],
  known_safe_hooks: [],
  unicode_analysis: true,
  check_ide_settings: true,
  owasp_mapping: true,
  trusted_api_domains: [],
  strict_collection: false,
  scan_collection_modes: ["default"],
  persona: "regular",
  runtime_mode: "offline",
  workflow_audits: { enabled: false },
  suppress_findings: [],
  scan_user_scope: true,
};

describe("cross-scan attribution — Layer 2 hidden-unicode rule", () => {
  it("does not flag sibling user-scope skills when the scan target is inside the home directory", async () => {
    const home = mkdtempSync(join(tmpdir(), "codegate-cross-scan-home-"));

    // Target skill: the scan target itself lives under the fake home dir,
    // exactly like `~/.codex/skills/<name>` in the bug report.
    mkdirSync(join(home, ".agents", "skills", "foo"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "foo", "SKILL.md"),
      "Clean skill body.\n",
      "utf8",
    );

    // Sibling skill with hidden Unicode under the same user-scope wildcard.
    // Under the old behavior this file would surface as a cross-scan finding
    // attributed to the `foo` scan.
    mkdirSync(join(home, ".agents", "skills", "bar"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "bar", "SKILL.md"),
      "Sibling skill​ with a hidden zero-width space.\n",
      "utf8",
    );

    const scanTarget = join(home, ".agents", "skills", "foo");

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget,
      config: BASE_CONFIG,
      homeDir: home,
    });

    const hiddenUnicodeFindings = report.findings.filter(
      (finding) => finding.rule_id === "rule-file-hidden-unicode",
    );

    // No finding should reference the sibling skill.
    expect(hiddenUnicodeFindings.some((finding) => finding.file_path.includes("skills/bar"))).toBe(
      false,
    );

    // No finding in the whole report should reference the sibling skill.
    expect(report.findings.some((finding) => finding.file_path.includes("skills/bar"))).toBe(false);
  });

  it("still flags hidden Unicode in a sibling skill when the scan target *is* the parent of both", async () => {
    // Sanity check: restricting sibling attribution must not hide in-target
    // findings. When the user scans the parent directory, both skills are
    // inside the scan target and both must be reported.
    const home = mkdtempSync(join(tmpdir(), "codegate-cross-scan-parent-home-"));
    mkdirSync(join(home, ".agents", "skills", "foo"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "foo", "SKILL.md"),
      "Clean skill body.\n",
      "utf8",
    );
    mkdirSync(join(home, ".agents", "skills", "bar"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "bar", "SKILL.md"),
      "Sibling skill​ with a hidden zero-width space.\n",
      "utf8",
    );

    const scanTarget = join(home, ".agents", "skills");

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget,
      config: BASE_CONFIG,
      homeDir: home,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "rule-file-hidden-unicode" &&
          finding.file_path.includes("bar/SKILL.md"),
      ),
    ).toBe(true);
  });

  it("preserves user-scope attribution when the scan target is not inside the home directory", async () => {
    // When scanning an arbitrary project root (outside the user's home),
    // user-scope files remain legitimate host-wide context and should still
    // be included as before.
    const home = mkdtempSync(join(tmpdir(), "codegate-cross-scan-external-home-"));
    const projectRoot = mkdtempSync(join(tmpdir(), "codegate-cross-scan-project-"));

    mkdirSync(join(home, ".agents", "skills", "bar"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "bar", "SKILL.md"),
      "Sibling skill​ with a hidden zero-width space.\n",
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: projectRoot,
      config: BASE_CONFIG,
      homeDir: home,
    });

    expect(
      report.findings.some(
        (finding) =>
          finding.rule_id === "rule-file-hidden-unicode" &&
          finding.file_path === "~/.agents/skills/bar/SKILL.md",
      ),
    ).toBe(true);
  });

  it("engine-level: file-target scan drops user-scope siblings", async () => {
    // Covers the case where runScanEngine is called directly with a file
    // target inside homeDir (library/embedded callers). The scope filter
    // in `shouldKeepUserScopeCandidate` rejects every candidate that is
    // not the target file itself.
    //
    // NB: the CLI stages file targets into a temp dir before calling the
    // engine — see the "CLI-level" test below for that path.
    const home = mkdtempSync(join(tmpdir(), "codegate-cross-scan-file-home-"));

    // Sibling: a skill with hidden Unicode under home.
    mkdirSync(join(home, ".agents", "skills", "bar"), { recursive: true });
    writeFileSync(
      join(home, ".agents", "skills", "bar", "SKILL.md"),
      "Sibling skill​ with hidden zero-width space.\n",
      "utf8",
    );

    // Target dir wrapping a single config file — simulates a consumer that
    // has already placed the file in a dedicated dir (runScanEngine
    // rejects bare files, hence the wrapper).
    const targetDir = join(home, ".claude");
    mkdirSync(targetDir, { recursive: true });
    writeFileSync(
      join(targetDir, "settings.json"),
      `{\n  "permissions": { "allow": [] }\n}\n`,
      "utf8",
    );

    const report = await runScanEngine({
      version: "0.1.0",
      scanTarget: targetDir,
      config: BASE_CONFIG,
      homeDir: home,
    });

    const leaked = report.findings.filter(
      (f) => typeof f.file_path === "string" && f.file_path.includes(".agents/skills/bar"),
    );
    expect(leaked).toEqual([]);
  });
});
