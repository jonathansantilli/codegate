import { describe, expect, it } from "vitest";
import { applyReportSummary, summarizeFindings } from "../../src/report-summary";
import type { Finding } from "../../src/types/finding";
import type { CodeGateReport } from "../../src/types/report";

function makeFinding(severity: Finding["severity"], overrides: Partial<Finding> = {}): Finding {
  return {
    rule_id: `rule-${severity.toLowerCase()}`,
    finding_id: `F-${severity}-${overrides.suppressed ? "suppressed" : "active"}`,
    severity,
    category: "COMMAND_EXEC",
    layer: "L2",
    file_path: ".mcp.json",
    location: { field: "mcpServers.bad.command" },
    description: "test finding",
    affected_tools: ["claude-code"],
    cve: null,
    owasp: ["ASI05"],
    cwe: "CWE-78",
    confidence: "HIGH",
    fixable: true,
    remediation_actions: ["remove_field"],
    suppressed: false,
    ...overrides,
  };
}

function emptyReport(findings: Finding[]): CodeGateReport {
  return {
    version: "0.1.0",
    scan_target: ".",
    timestamp: "2026-03-06T00:00:00.000Z",
    kb_version: "2026-03-06",
    tools_detected: ["claude-code"],
    findings,
    summary: {
      total: 0,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      fixable: 0,
      suppressed: 0,
      exit_code: 0,
    },
  };
}

describe("report finalization helpers", () => {
  it("summarizes findings with threshold-aware exit codes", () => {
    const findings = [
      makeFinding("LOW"),
      makeFinding("HIGH", { suppressed: true }),
      makeFinding("MEDIUM"),
    ];

    const summary = summarizeFindings(findings, "medium");

    expect(summary).toEqual({
      total: 3,
      by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 1, INFO: 0 },
      fixable: 3,
      suppressed: 1,
      exit_code: 2,
    });
  });

  it("rebuilds report summary without changing report metadata", () => {
    const report = emptyReport([makeFinding("LOW"), makeFinding("INFO", { fixable: false })]);

    const updated = applyReportSummary(report, "high");

    expect(updated.version).toBe(report.version);
    expect(updated.scan_target).toBe(report.scan_target);
    expect(updated.kb_version).toBe(report.kb_version);
    expect(updated.summary).toEqual({
      total: 2,
      by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 1 },
      fixable: 1,
      suppressed: 0,
      exit_code: 1,
    });
  });
});
