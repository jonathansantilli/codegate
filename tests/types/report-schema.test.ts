import { describe, expect, it } from "vitest";
import { FINDING_CATEGORIES, SEVERITIES, type Finding } from "../../src/types/finding";
import { createEmptyReport } from "../../src/types/report";
import type { DiscoveryResult } from "../../src/types/discovery";

describe("task 05 report and finding contracts", () => {
  it("exposes stable severity and category sets", () => {
    expect(SEVERITIES).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
    expect(FINDING_CATEGORIES).toContain("ENV_OVERRIDE");
    expect(FINDING_CATEGORIES).toContain("PARSE_ERROR");
  });

  it("creates an empty report with deterministic defaults", () => {
    const report = createEmptyReport({
      version: "0.1.0",
      scanTarget: ".",
      kbVersion: "2026-02-28",
      toolsDetected: ["claude"],
      exitCode: 0,
    });

    expect(report.version).toBe("0.1.0");
    expect(report.scan_target).toBe(".");
    expect(report.findings).toEqual([]);
    expect(report.summary.total).toBe(0);
    expect(report.summary.exit_code).toBe(0);
  });

  it("keeps required IDs on findings and discovery records", () => {
    const finding: Finding = {
      rule_id: "env-base-url-override",
      finding_id: "ENV_OVERRIDE-.claude/settings.json-env.ANTHROPIC_BASE_URL",
      fingerprint: "sha256:test",
      severity: "CRITICAL",
      category: "ENV_OVERRIDE",
      layer: "L2",
      file_path: ".claude/settings.json",
      location: { field: "env.ANTHROPIC_BASE_URL" },
      description: "Redirects traffic",
      affected_tools: ["claude-code"],
      owasp: ["ASI03"],
      cwe: "CWE-522",
      confidence: "HIGH",
      fixable: true,
      remediation_actions: ["remove_field"],
      metadata: {
        sources: [".claude/settings.json", "env.ANTHROPIC_BASE_URL"],
        sinks: ["api-redirect"],
        referenced_secrets: ["ANTHROPIC_BASE_URL"],
        risk_tags: ["endpoint-override", "exfiltration"],
        origin: "report-schema-test",
      },
      suppressed: false,
    };

    const discovery: DiscoveryResult = {
      tool: "claude-code",
      configPath: ".claude/settings.json",
      absolutePath: "/tmp/project/.claude/settings.json",
      format: "jsonc",
      scope: "project",
      riskSurfaces: ["env_override"],
      isSymlink: false,
    };

    expect(finding.rule_id).toBeTruthy();
    expect(finding.finding_id).toBeTruthy();
    expect(discovery.tool).toBe("claude-code");
  });
});
