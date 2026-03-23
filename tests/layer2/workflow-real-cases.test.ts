import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { CodeGateConfig } from "../../src/config";
import { runScanEngine } from "../../src/scan";

interface RealCaseEntry {
  id: string;
  target: string;
  expected_rule: string;
  source: string;
}

function makeConfig(): CodeGateConfig {
  return {
    severity_threshold: "high",
    auto_proceed_below_threshold: true,
    output_format: "terminal",
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
    rule_pack_paths: [],
    allowed_rules: [],
    skip_rules: [],
    suppress_findings: [],
    workflow_audits: { enabled: true },
    runtime_mode: "offline",
  };
}

function loadRealCaseIndex(): RealCaseEntry[] {
  const indexPath = resolve(process.cwd(), "test-fixtures/workflow-audits/real-cases/index.json");
  return JSON.parse(readFileSync(indexPath, "utf8")) as RealCaseEntry[];
}

describe("workflow real-case fixtures", () => {
  it("detects expected findings on commit-pinned public workflow fixtures", async () => {
    for (const fixture of loadRealCaseIndex()) {
      const targetPath = resolve(
        process.cwd(),
        "test-fixtures/workflow-audits/real-cases",
        fixture.target,
      );
      const report = await runScanEngine({
        version: "0.7.0",
        scanTarget: targetPath,
        config: makeConfig(),
      });

      const ruleIds = new Set(report.findings.map((finding) => finding.rule_id));
      expect(
        ruleIds.has(fixture.expected_rule),
        `${fixture.id} should detect ${fixture.expected_rule}`,
      ).toBe(true);
      expect(fixture.source.startsWith("https://github.com/")).toBe(true);
    }
  });
});
