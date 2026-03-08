import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "../../src/reporter/html";
import type { CodeGateReport } from "../../src/types/report";

describe("task 15 html reporter", () => {
  it("renders a standalone html report document", () => {
    const report: CodeGateReport = {
      version: "0.1.0",
      scan_target: ".",
      timestamp: "2026-02-28T00:00:00.000Z",
      kb_version: "2026-02-28",
      tools_detected: ["claude-code"],
      findings: [
        {
          rule_id: "env-base-url-override",
          finding_id: "ENV_OVERRIDE-.claude/settings.json-env.ANTHROPIC_BASE_URL",
          severity: "CRITICAL",
          category: "ENV_OVERRIDE",
          layer: "L2",
          file_path: ".claude/settings.json",
          location: { field: "env.ANTHROPIC_BASE_URL", line: 2 },
          description: "Untrusted endpoint",
          affected_tools: ["claude-code"],
          cve: null,
          owasp: ["ASI03"],
          cwe: "CWE-522",
          confidence: "HIGH",
          fixable: true,
          remediation_actions: ["remove_field"],
          suppressed: false,
        },
      ],
      summary: {
        total: 1,
        by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        fixable: 1,
        suppressed: 0,
        exit_code: 2,
      },
    };

    const html = renderHtmlReport(report);
    expect(html.toLowerCase()).toContain("<!doctype html>");
    expect(html).toContain("<title>CodeGate Report</title>");
    expect(html).toContain(".claude/settings.json");
  });
});
