import { describe, expect, it } from "vitest";
import { renderJsonReport } from "../../src/reporter/json";
import { renderSarifReport } from "../../src/reporter/sarif";
import type { CodeGateReport } from "../../src/types/report";

function buildReport(): CodeGateReport {
  return {
    version: "0.2.2",
    scan_target: ".",
    timestamp: "2026-02-28T00:00:00.000Z",
    kb_version: "2026-02-28",
    tools_detected: ["claude-code"],
    findings: [
      {
        rule_id: "mcp-server-first-seen",
        finding_id: "NEW_SERVER-@org/mcp-a",
        severity: "INFO",
        category: "NEW_SERVER",
        layer: "L2",
        file_path: ".mcp.json",
        location: { field: "mcpServers.serverA" },
        description: "Server first seen.",
        affected_tools: ["claude-code"],
        cve: null,
        owasp: ["ASI08"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [],
        suppressed: false,
      },
      {
        rule_id: "mcp-server-config-change",
        finding_id: "CONFIG_CHANGE-@org/mcp-b",
        severity: "HIGH",
        category: "CONFIG_CHANGE",
        layer: "L2",
        file_path: ".mcp.json",
        location: { field: "mcpServers.serverB" },
        description: "Server changed.",
        affected_tools: ["claude-code"],
        cve: null,
        owasp: ["ASI08"],
        cwe: "CWE-829",
        confidence: "HIGH",
        fixable: false,
        remediation_actions: [],
        suppressed: false,
      },
    ],
    summary: {
      total: 2,
      by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 1 },
      fixable: 0,
      suppressed: 0,
      exit_code: 2,
    },
  };
}

describe("task 31 scan-state reporting", () => {
  it("preserves scan-state categories in json output", () => {
    const parsed = JSON.parse(renderJsonReport(buildReport())) as CodeGateReport;
    expect(parsed.findings.map((finding) => finding.category)).toEqual(["NEW_SERVER", "CONFIG_CHANGE"]);
  });

  it("preserves scan-state categories and fingerprints in sarif output", () => {
    const sarif = JSON.parse(renderSarifReport(buildReport())) as {
      runs: Array<{
        tool: { driver: { rules: Array<{ properties: { category: string } }> } };
        results: Array<{ properties: { finding_id: string; category: string } }>;
      }>;
    };

    const categories = sarif.runs[0]?.results.map((result) => result.properties.category) ?? [];
    const findingIds = sarif.runs[0]?.results.map((result) => result.properties.finding_id) ?? [];

    expect(categories).toEqual(["NEW_SERVER", "CONFIG_CHANGE"]);
    expect(findingIds).toEqual(["NEW_SERVER-@org/mcp-a", "CONFIG_CHANGE-@org/mcp-b"]);
    expect(
      sarif.runs[0]?.tool.driver.rules.map((rule) => rule.properties.category),
    ).toEqual(["NEW_SERVER", "CONFIG_CHANGE"]);
  });
});
